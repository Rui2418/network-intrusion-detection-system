#ifndef _FIREWALL_IOCTL_H_
#define _FIREWALL_IOCTL_H_

#include <linux/ioctl.h>

#define FIREWALL_MAJOR 124
#define DEVICE_NAME "/dev/firewall"

#define FIREWALL_MAGIC 'F'

#define CMD_SET_ENABLE      _IOW(FIREWALL_MAGIC, 1, int)
#define CMD_GET_STATUS      _IOR(FIREWALL_MAGIC, 2, struct firewall_status)
#define CMD_ADD_RULE        _IOW(FIREWALL_MAGIC, 3, struct firewall_rule)
#define CMD_DEL_RULE        _IOW(FIREWALL_MAGIC, 4, int)
#define CMD_UPDATE_RULE     _IOW(FIREWALL_MAGIC, 5, struct firewall_rule)
#define CMD_LIST_RULES      _IOR(FIREWALL_MAGIC, 6, struct firewall_rule_list)
#define CMD_GET_STATS       _IOR(FIREWALL_MAGIC, 7, struct firewall_stats)
#define CMD_SET_DEFAULT     _IOW(FIREWALL_MAGIC, 8, int)
#define CMD_CLEAR_STATS     _IO(FIREWALL_MAGIC, 9)
#define CMD_GET_RULE_COUNT  _IOR(FIREWALL_MAGIC, 10, int)

#define FW_ACTION_ACCEPT 0
#define FW_ACTION_DROP   1
#define FW_DEFAULT_ACCEPT 0
#define FW_DEFAULT_DENY   1
#define MAX_RULES 256

struct firewall_rule {
    unsigned int rule_id;
    unsigned int priority;
    unsigned int protocol;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned int action;
    unsigned int enabled;
    unsigned int hit_count;
    unsigned int reserved[4];
};

struct firewall_rule_list {
    unsigned int count;
    struct firewall_rule rules[MAX_RULES];
};

struct firewall_status {
    unsigned int enabled;
    unsigned int default_policy;
    unsigned int rule_count;
    unsigned int uptime_seconds;
};

struct firewall_stats {
    unsigned long long total_checked;
    unsigned long long total_dropped;
    unsigned long long total_accepted;
    unsigned int protocol_stats[256];
};

#endif
