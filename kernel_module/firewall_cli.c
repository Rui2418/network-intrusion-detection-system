#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

#include "firewall_ioctl.h"

static void usage(char *name)
{
    printf("Usage:\n  %s                     Disable firewall\n", name);
    printf("  %s enable              Enable firewall\n", name);
    printf("  %s status              Show status\n", name);
    printf("  %s rule add -p proto -x saddr -y daddr -m sport -n dport -a action -r prio\n", name);
    printf("  %s rule del <id>\n", name);
    printf("  %s rule list\n", name);
    printf("  %s stats\n", name);
    printf("  %s default accept|deny\n", name);
}

static int open_dev(void)
{
    int fd;
    struct stat st;
    if (stat(DEVICE_NAME, &st) != 0) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "mknod %s c %d 0", DEVICE_NAME, FIREWALL_MAJOR);
        system(cmd);
    }
    fd = open(DEVICE_NAME, O_RDWR);
    if (fd < 0) perror(DEVICE_NAME);
    return fd;
}

int main(int argc, char *argv[])
{
    int fd, ret;

    if (argc < 2) {
        fd = open_dev(); if (fd < 0) return 1;
        ret = 0; ioctl(fd, CMD_SET_ENABLE, &ret);
        printf("Firewall DISABLED\n"); close(fd); return 0;
    }

    if (!strcmp(argv[1], "enable")) {
        fd = open_dev(); if (fd < 0) return 1;
        ret = 1; ioctl(fd, CMD_SET_ENABLE, &ret);
        printf("Firewall ENABLED\n"); close(fd); return 0;
    }

    if (!strcmp(argv[1], "status")) {
        struct firewall_status st;
        fd = open_dev(); if (fd < 0) return 1;
        if (ioctl(fd, CMD_GET_STATUS, &st) < 0) { perror("ioctl"); close(fd); return 1; }
        printf("Status:  %s\n", st.enabled ? "ENABLED" : "DISABLED");
        printf("Policy:  %s\n", st.default_policy ? "DENY" : "ACCEPT");
        printf("Rules:   %u\n", st.rule_count);
        printf("Uptime:  %u sec\n", st.uptime_seconds);
        close(fd); return 0;
    }

    if (!strcmp(argv[1], "stats")) {
        struct firewall_stats st;
        fd = open_dev(); if (fd < 0) return 1;
        if (ioctl(fd, CMD_GET_STATS, &st) < 0) { perror("ioctl"); close(fd); return 1; }
        printf("Checked:  %llu\n", st.total_checked);
        printf("Accepted: %llu\n", st.total_accepted);
        printf("Dropped:  %llu\n", st.total_dropped);
        if (st.total_checked) printf("Rate:     %.1f%%\n", 100.0 * st.total_dropped / st.total_checked);
        printf("ICMP: %u  TCP: %u  UDP: %u\n", st.protocol_stats[1], st.protocol_stats[6], st.protocol_stats[17]);
        close(fd); return 0;
    }

    if (!strcmp(argv[1], "default")) {
        int p;
        if (argc < 3) { printf("Use: %s default accept|deny\n", argv[0]); return 1; }
        if (!strcmp(argv[2], "deny")) p = FW_DEFAULT_DENY;
        else if (!strcmp(argv[2], "accept")) p = FW_DEFAULT_ACCEPT;
        else { printf("Invalid\n"); return 1; }
        fd = open_dev(); if (fd < 0) return 1;
        ioctl(fd, CMD_SET_DEFAULT, &p);
        printf("Default policy: %s\n", argv[2]);
        close(fd); return 0;
    }

    if (!strcmp(argv[1], "rule")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        fd = open_dev(); if (fd < 0) return 1;

        if (!strcmp(argv[2], "list")) {
            struct firewall_rule_list rl;
            if (ioctl(fd, CMD_LIST_RULES, &rl) < 0) { perror("ioctl"); close(fd); return 1; }
            printf("%-4s %-6s %-5s %-16s %-16s %-6s %-6s %-8s %s\n",
                "ID","Prior","Proto","SrcIP","DstIP","SPort","DPort","Action","On");
            for (unsigned i = 0; i < rl.count; i++) {
                struct firewall_rule *r = &rl.rules[i];
                char sa[16]="*", da[16]="*";
                struct in_addr ia;
                if (r->saddr) { ia.s_addr = r->saddr; strcpy(sa, inet_ntoa(ia)); }
                if (r->daddr) { ia.s_addr = r->daddr; strcpy(da, inet_ntoa(ia)); }
                const char *proto = (r->protocol == 0) ? "any" : (r->protocol==1)?"icmp":(r->protocol==6)?"tcp":(r->protocol==17)?"udp":"?";
                printf("%-4u %-6u %-5s %-16s %-16s %-6u %-6u %-8s %s\n",
                    r->rule_id, r->priority, proto, sa, da,
                    r->sport, r->dport, r->action?"DROP":"ACCEPT", r->enabled?"Y":"N");
            }
            close(fd); return 0;
        }

        if (!strcmp(argv[2], "del")) {
            int id; if (argc < 4) { printf("Need rule id\n"); close(fd); return 1; }
            id = atoi(argv[3]);
            ioctl(fd, CMD_DEL_RULE, &id);
            printf("Rule %d deleted\n", id);
            close(fd); return 0;
        }

        if (!strcmp(argv[2], "add")) {
            struct firewall_rule rule;
            memset(&rule, 0, sizeof(rule));
            rule.enabled = 1; rule.action = FW_ACTION_DROP; rule.priority = 100;
            optind = 3;
            int opt;
            while ((opt = getopt(argc, argv, "p:x:y:m:n:a:r:")) != -1) {
                switch (opt) {
                    case 'p':
                        if (!strcmp(optarg,"any")) rule.protocol=0;
                        else if (!strcmp(optarg,"icmp")) rule.protocol=1;
                        else if (!strcmp(optarg,"tcp")) rule.protocol=6;
                        else if (!strcmp(optarg,"udp")) rule.protocol=17;
                        else rule.protocol=atoi(optarg);
                        break;
                    case 'x': inet_aton(optarg, (struct in_addr*)&rule.saddr); break;
                    case 'y': inet_aton(optarg, (struct in_addr*)&rule.daddr); break;
                    case 'm': rule.sport = atoi(optarg); break;
                    case 'n': rule.dport = atoi(optarg); break;
                    case 'a': rule.action = !strcmp(optarg,"accept") ? FW_ACTION_ACCEPT : FW_ACTION_DROP; break;
                    case 'r': rule.priority = atoi(optarg); break;
                    default: usage(argv[0]); close(fd); return 1;
                }
            }
            ioctl(fd, CMD_ADD_RULE, &rule);
            printf("Rule added\n");
            close(fd); return 0;
        }
        close(fd); usage(argv[0]); return 1;
    }

    usage(argv[0]); return 1;
}
