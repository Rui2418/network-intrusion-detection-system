import struct
import os
import sys

DEVICE_PATH = "/dev/firewall"
IS_LINUX = sys.platform.startswith('linux')

if IS_LINUX:
    try:
        import fcntl
        _fcntl_ok = True
    except ImportError:
        _fcntl_ok = False
        IS_LINUX = False
else:
    _fcntl_ok = False
    IS_LINUX = False

def _mock_data():
    return {"enabled": False, "default_policy": "accept", "rule_count": 0, "uptime_seconds": 0}


def set_enable(enabled):
    if not IS_LINUX:
        return


def get_status():
    if not IS_LINUX:
        return _mock_data()

    if not os.path.exists(DEVICE_PATH):
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
    if not IS_LINUX:
        return
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        buf = struct.pack('IIIIHHIIIIIII',
            0, data.get('priority', 100),
            data.get('protocol', 0),
            _ip_to_int(data.get('saddr', '')),
            _ip_to_int(data.get('daddr', '')),
            data.get('sport', 0),
            data.get('dport', 0),
            0 if data.get('action', 'drop') == 'accept' else 1,
            1 if data.get('enabled', True) else 0,
            0, 0, 0, 0, 0)
        _ioctl_ADD_RULE(fd, buf)
    except OSError:
        pass
    finally:
        if fd is not None:
            os.close(fd)


def del_rule(rule_id):
    if not IS_LINUX:
        return
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        _ioctl_DEL_RULE(fd, rule_id)
    except OSError:
        pass
    finally:
        if fd is not None:
            os.close(fd)


def update_rule(data):
    if not IS_LINUX:
        return
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        buf = struct.pack('IIIIHHIIIIIII',
            data.get('id', 0), data.get('priority', 100),
            data.get('protocol', 0),
            _ip_to_int(data.get('saddr', '')),
            _ip_to_int(data.get('daddr', '')),
            data.get('sport', 0), data.get('dport', 0),
            0 if data.get('action', 'drop') == 'accept' else 1,
            1 if data.get('enabled', True) else 0,
            0, 0, 0, 0, 0)
        _ioctl_UPDATE_RULE(fd, buf)
    except OSError:
        pass
    finally:
        if fd is not None:
            os.close(fd)


def list_rules():
    if not IS_LINUX:
        return []
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        buf = _ioctl_LIST_RULES(fd)
        count = struct.unpack_from('I', buf, 0)[0]
        rules = []
        fmt = 'IIIIHHIIIIIII'
        sz = struct.calcsize(fmt)
        for i in range(count):
            f = struct.unpack_from(fmt, buf, 4 + i * sz)
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


def get_stats():
    if not IS_LINUX:
        return {"total_checked": 0, "total_dropped": 0, "total_accepted": 0, "drop_rate": 0, "protocols": {"icmp": 0, "tcp": 0, "udp": 0}}
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
    if not IS_LINUX:
        return
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        _ioctl_SET_DEFAULT(fd, policy)
    except OSError:
        pass
    finally:
        if fd is not None:
            os.close(fd)


def clear_stats():
    if not IS_LINUX:
        return
    fd = None
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
        _ioctl_CLEAR_STATS(fd)
    except OSError:
        pass
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
    fcntl.ioctl(fd, _ioc(1, FIREWALL_MAGIC, 3, 64), buf)

def _ioctl_DEL_RULE(fd, rule_id):
    fcntl.ioctl(fd, _ioc(1, FIREWALL_MAGIC, 4, 4), struct.pack('i', rule_id))

def _ioctl_UPDATE_RULE(fd, buf):
    fcntl.ioctl(fd, _ioc(1, FIREWALL_MAGIC, 5, 64), buf)

def _ioctl_LIST_RULES(fd):
    return fcntl.ioctl(fd, _ioc(2, FIREWALL_MAGIC, 6, 16388), b'\x00' * 16388)

def _ioctl_GET_STATS(fd):
    return fcntl.ioctl(fd, _ioc(2, FIREWALL_MAGIC, 7, 1040), b'\x00' * 1040)

def _ioctl_SET_DEFAULT(fd, policy):
    fcntl.ioctl(fd, _ioc(1, FIREWALL_MAGIC, 8, 4), struct.pack('i', 1 if policy == 'deny' else 0))

def _ioctl_CLEAR_STATS(fd):
    fcntl.ioctl(fd, _ioc(0, FIREWALL_MAGIC, 9, 0), b'')


def _ip_to_int(ip):
    if not ip: return 0
    parts = ip.split('.')
    if len(parts) != 4: return 0
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

def _int_to_ip(v):
    if v == 0: return ''
    return f"{(v>>24)&0xFF}.{(v>>16)&0xFF}.{(v>>8)&0xFF}.{v&0xFF}"

def _proto_name(n):
    return {0: 'any', 1: 'icmp', 6: 'tcp', 17: 'udp'}.get(n, str(n))
