import copy
import ipaddress
import socket
import struct
import os
import sys
import ctypes
import ctypes.util

DEVICE_PATH = "/dev/firewall"
# 真实 IPS 联动只在 Linux 且存在 /dev/firewall 设备时启用，其余环境走模拟状态。
IS_LINUX = sys.platform.startswith('linux')

_libc = None
if IS_LINUX:
    try:
        import fcntl
        _fcntl_ok = True
        libc_name = ctypes.util.find_library("c")
        if libc_name:
            _libc = ctypes.CDLL(libc_name, use_errno=True)
    except ImportError:
        _fcntl_ok = False
        IS_LINUX = False
else:
    _fcntl_ok = False
    IS_LINUX = False

# 与内核模块约定的二进制规则结构，Python 侧只负责打包和 ioctl 边界转换。
FWRULE_FMT = 'IIIIIHHIIIIIII'

_MOCK_RULES = []
_MOCK_NEXT_RULE_ID = 1
_MOCK_ENABLED = False
_MOCK_DEFAULT_POLICY = "accept"
_MOCK_STATS = {
    "total_checked": 0,
    "total_dropped": 0,
    "total_accepted": 0,
    "drop_rate": 0,
    "protocols": {"icmp": 0, "tcp": 0, "udp": 0},
}


def is_kernel_available():
    return IS_LINUX and os.path.exists(DEVICE_PATH)


def is_mock_mode():
    return not is_kernel_available()


def _mock_data():
    return {
        "enabled": _MOCK_ENABLED,
        "default_policy": _MOCK_DEFAULT_POLICY,
        "rule_count": len(_MOCK_RULES),
        "uptime_seconds": 0,
    }


def set_enable(enabled):
    global _MOCK_ENABLED
    if is_mock_mode():
        _MOCK_ENABLED = bool(enabled)
        return
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        _ioctl_SET_ENABLE(fd, 1 if enabled else 0)
    except OSError as e:
        raise RuntimeError(f"ioctl SET_ENABLE failed: {e}")
    finally:
        if fd is not None:
            os.close(fd)


def get_status():
    if is_mock_mode():
        return _mock_data()

    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        buf = _ioctl_GET_STATUS(fd)
        enabled, dp, rc, up = struct.unpack('IIII', buf)
        return {
            'enabled': bool(enabled),
            'default_policy': 'deny' if dp else 'accept',
            'rule_count': rc,
            'uptime_seconds': up,
        }
    except (OSError, struct.error):
        return _mock_data()
    finally:
        if fd is not None:
            os.close(fd)


def add_rule(data):
    global _MOCK_NEXT_RULE_ID
    rule = _normalize_rule(data)
    if is_mock_mode():
        rule['id'] = _MOCK_NEXT_RULE_ID
        _MOCK_NEXT_RULE_ID += 1
        _MOCK_RULES.append(rule)
        return
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        buf = _pack_rule(rule)
        _ioctl_ADD_RULE(fd, buf)
    except OSError as e:
        raise RuntimeError(f"ioctl ADD_RULE failed: {e}")
    finally:
        if fd is not None:
            os.close(fd)


def del_rule(rule_id):
    if is_mock_mode():
        before = len(_MOCK_RULES)
        _MOCK_RULES[:] = [rule for rule in _MOCK_RULES if rule['id'] != int(rule_id)]
        return len(_MOCK_RULES) != before
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        _ioctl_DEL_RULE(fd, rule_id)
        return True
    except OSError as e:
        raise RuntimeError(f"ioctl DEL_RULE failed: {e}")
    finally:
        if fd is not None:
            os.close(fd)


def update_rule(data):
    rule = _normalize_rule(data)
    if is_mock_mode():
        for index, existing in enumerate(_MOCK_RULES):
            if existing['id'] == rule['id']:
                rule['hit_count'] = existing.get('hit_count', 0)
                _MOCK_RULES[index] = rule
                return True
        return False
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        buf = _pack_rule(rule)
        _ioctl_UPDATE_RULE(fd, buf)
        return True
    except OSError as e:
        raise RuntimeError(f"ioctl UPDATE_RULE failed: {e}")
    finally:
        if fd is not None:
            os.close(fd)


def list_rules():
    if is_mock_mode():
        return copy.deepcopy(_MOCK_RULES)
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        buf = _ioctl_LIST_RULES(fd)
        count = struct.unpack_from('I', buf, 0)[0]
        rules = []
        sz = struct.calcsize(FWRULE_FMT)
        for i in range(count):
            f = struct.unpack_from(FWRULE_FMT, buf, 4 + i * sz)
            rules.append({
                'id': f[0], 'priority': f[1],
                'protocol_num': f[2],
                'protocol': _proto_name(f[2]),
                'saddr': _int_to_ip(f[3]), 'daddr': _int_to_ip(f[4]),
                'sport': f[5], 'dport': f[6],
                'action': 'accept' if f[7] == 0 else 'drop',
                'enabled': bool(f[8]),
                'hit_count': f[9],
            })
        return rules
    except (OSError, struct.error):
        return []
    finally:
        if fd is not None:
            os.close(fd)


def record_mock_packet(action="accept", protocol="tcp"):
    if not is_mock_mode():
        return False
    normalized_protocol = str(protocol or "tcp").lower()
    if normalized_protocol not in _MOCK_STATS["protocols"]:
        normalized_protocol = "tcp"
    _MOCK_STATS["total_checked"] += 1
    _MOCK_STATS["protocols"][normalized_protocol] += 1
    if action == "drop":
        _MOCK_STATS["total_dropped"] += 1
    else:
        _MOCK_STATS["total_accepted"] += 1
    total_checked = _MOCK_STATS["total_checked"]
    _MOCK_STATS["drop_rate"] = round(_MOCK_STATS["total_dropped"] / total_checked * 100, 1) if total_checked else 0
    return True


def get_stats():
    if is_mock_mode():
        return copy.deepcopy(_MOCK_STATS)
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        buf = _ioctl_GET_STATS(fd)
        tc = struct.unpack_from('Q', buf, 0)[0]
        td = struct.unpack_from('Q', buf, 8)[0]
        ta = struct.unpack_from('Q', buf, 16)[0]
        icmp = struct.unpack_from('I', buf, 24 + 4 * 1)[0]
        tcp = struct.unpack_from('I', buf, 24 + 4 * 6)[0]
        udp = struct.unpack_from('I', buf, 24 + 4 * 17)[0]
        dr = (td / tc * 100) if tc > 0 else 0
        return {
            'total_checked': tc, 'total_dropped': td, 'total_accepted': ta,
            'drop_rate': round(dr, 1),
            'protocols': {'icmp': icmp, 'tcp': tcp, 'udp': udp},
        }
    except (OSError, struct.error):
        return {"total_checked": 0, "total_dropped": 0, "total_accepted": 0, "drop_rate": 0, "protocols": {"icmp": 0, "tcp": 0, "udp": 0}}
    finally:
        if fd is not None:
            os.close(fd)


def set_default_policy(policy):
    global _MOCK_DEFAULT_POLICY
    if is_mock_mode():
        _MOCK_DEFAULT_POLICY = 'deny' if policy == 'deny' else 'accept'
        return
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        _ioctl_SET_DEFAULT(fd, policy)
    except OSError as e:
        raise RuntimeError(f"ioctl SET_DEFAULT failed: {e}")
    finally:
        if fd is not None:
            os.close(fd)


def clear_stats():
    if is_mock_mode():
        _MOCK_STATS.update({
            "total_checked": 0,
            "total_dropped": 0,
            "total_accepted": 0,
            "drop_rate": 0,
            "protocols": {"icmp": 0, "tcp": 0, "udp": 0},
        })
        return
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        _ioctl_CLEAR_STATS(fd)
    except OSError as e:
        raise RuntimeError(f"ioctl CLEAR_STATS failed: {e}")
    finally:
        if fd is not None:
            os.close(fd)


def _ioc(dir, typ, nr, size):
    return (dir << 30) | (typ << 8) | (nr << 0) | (size << 16)

FIREWALL_MAGIC = ord('F')

def _ioctl_SET_ENABLE(fd, val):
    fcntl.ioctl(fd, _ioc(1, FIREWALL_MAGIC, 1, 4), struct.pack('i', val))

def _ioctl_GET_STATUS(fd):
    return fcntl.ioctl(fd, _ioc(2, FIREWALL_MAGIC, 2, 16), b'\x00' * 16)

def _ioctl_ADD_RULE(fd, buf):
    fcntl.ioctl(fd, _ioc(1, FIREWALL_MAGIC, 3, 52), buf)

def _ioctl_DEL_RULE(fd, rule_id):
    fcntl.ioctl(fd, _ioc(1, FIREWALL_MAGIC, 4, 4), struct.pack('i', rule_id))

def _ioctl_UPDATE_RULE(fd, buf):
    fcntl.ioctl(fd, _ioc(1, FIREWALL_MAGIC, 5, 52), buf)

def _ioctl_LIST_RULES(fd):
    if _libc:
        buf = ctypes.create_string_buffer(13316)
        ret = _libc.ioctl(fd, _ioc(2, FIREWALL_MAGIC, 6, 13316), buf)
        if ret < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return buf.raw
    return fcntl.ioctl(fd, _ioc(2, FIREWALL_MAGIC, 6, 13316), b'\x00' * 13316)


def _ioctl_GET_STATS(fd):
    if _libc:
        buf = ctypes.create_string_buffer(1048)
        ret = _libc.ioctl(fd, _ioc(2, FIREWALL_MAGIC, 7, 1048), buf)
        if ret < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return buf.raw
    return fcntl.ioctl(fd, _ioc(2, FIREWALL_MAGIC, 7, 1048), b'\x00' * 1048)

def _ioctl_SET_DEFAULT(fd, policy):
    fcntl.ioctl(fd, _ioc(1, FIREWALL_MAGIC, 8, 4), struct.pack('i', 1 if policy == 'deny' else 0))

def _ioctl_CLEAR_STATS(fd):
    fcntl.ioctl(fd, _ioc(0, FIREWALL_MAGIC, 9, 0), b'')


def _pack_rule(rule):
    return struct.pack('IIIIIHHIIIIIII',
        rule.get('id', 0), rule.get('priority', 100),
        rule.get('protocol_num', 0),
        _ip_to_int(rule.get('saddr', '')),
        _ip_to_int(rule.get('daddr', '')),
        rule.get('sport', 0),
        rule.get('dport', 0),
        0 if rule.get('action', 'drop') == 'accept' else 1,
        1 if rule.get('enabled', True) else 0,
        0, 0, 0, 0, 0)


def _proto_num(value):
    if isinstance(value, int):
        return value
    return {'any': 0, 'icmp': 1, 'tcp': 6, 'udp': 17}.get(str(value).lower(), 0)


def _normalize_ip(value):
    value = str(value or '').strip()
    if not value:
        return ''
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ''


def _normalize_rule(data):
    protocol_num = _proto_num(data.get('protocol', data.get('protocol_num', 0)))
    return {
        'id': int(data.get('id', 0) or 0),
        'priority': int(data.get('priority', 100) or 100),
        'protocol_num': protocol_num,
        'protocol': _proto_name(protocol_num),
        'saddr': _normalize_ip(data.get('saddr', '')),
        'daddr': _normalize_ip(data.get('daddr', '')),
        'sport': int(data.get('sport', 0) or 0),
        'dport': int(data.get('dport', 0) or 0),
        'action': 'accept' if data.get('action') == 'accept' else 'drop',
        'enabled': bool(data.get('enabled', True)),
        'hit_count': int(data.get('hit_count', 0) or 0),
    }


def _ip_to_int(ip):
    if not ip: return 0
    return struct.unpack('I', socket.inet_aton(str(ip)))[0]


def _int_to_ip(v):
    if v == 0: return ''
    return socket.inet_ntoa(struct.pack('I', v))


def _proto_name(n):
    return {0: 'any', 1: 'icmp', 6: 'tcp', 17: 'udp'}.get(n, str(n))
