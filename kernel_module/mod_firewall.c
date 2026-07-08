#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/jiffies.h>

#include "firewall_ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IDS-IPS Team");
MODULE_DESCRIPTION("IPS kernel module for IDS-IPS unified system");

static int major = FIREWALL_MAJOR;
static int enable_flag = 0;
static int default_policy = FW_DEFAULT_ACCEPT;
static unsigned long start_time = 0;
static unsigned int next_rule_id = 1;

static struct nf_hook_ops myhook;
static unsigned long long total_checked = 0, total_dropped = 0, total_accepted = 0;
static unsigned int protocol_stats[256] = {0};
static LIST_HEAD(rule_list);
static int rule_count = 0;

struct rule_entry {
    struct firewall_rule rule;
    struct list_head list;
};

static int match_rule(struct firewall_rule *r, unsigned int proto,
    unsigned int saddr, unsigned int daddr, unsigned short sport, unsigned short dport)
{
    if (r->protocol != 0 && r->protocol != proto) return 0;
    if (r->saddr != 0 && r->saddr != saddr) return 0;
    if (r->daddr != 0 && r->daddr != daddr) return 0;
    if (r->sport != 0 && r->sport != sport) return 0;
    if (r->dport != 0 && r->dport != dport) return 0;
    return 1;
}

static unsigned int hook_func(void *priv, struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    unsigned short sport = 0, dport = 0;
    struct rule_entry *entry;
    unsigned int result;

    if (!enable_flag) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    total_checked++;
    protocol_stats[iph->protocol]++;

    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));
        sport = ntohs(tcph->source);
        dport = ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = (struct udphdr *)(skb->data + (iph->ihl * 4));
        sport = ntohs(udph->source);
        dport = ntohs(udph->dest);
    }

    result = (default_policy == FW_DEFAULT_ACCEPT) ? NF_ACCEPT : NF_DROP;

    list_for_each_entry(entry, &rule_list, list) {
        if (!entry->rule.enabled) continue;
        if (match_rule(&entry->rule, iph->protocol,
            iph->saddr, iph->daddr, sport, dport)) {
            entry->rule.hit_count++;
            if (entry->rule.action == FW_ACTION_DROP) result = NF_DROP;
            else result = NF_ACCEPT;
            break;
        }
    }

    if (result == NF_DROP) total_dropped++;
    else total_accepted++;
    return result;
}

static int add_rule(struct firewall_rule *rule)
{
    struct rule_entry *entry;
    if (rule_count >= MAX_RULES) return -ENOSPC;
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) return -ENOMEM;
    memcpy(&entry->rule, rule, sizeof(*rule));
    entry->rule.rule_id = next_rule_id++;
    entry->rule.hit_count = 0;
    list_add_tail(&entry->list, &rule_list);
    rule_count++;
    return entry->rule.rule_id;
}

static int del_rule(unsigned int rule_id)
{
    struct rule_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &rule_list, list) {
        if (entry->rule.rule_id == rule_id) {
            list_del(&entry->list);
            kfree(entry);
            rule_count--;
            return 0;
        }
    }
    return -ENOENT;
}

static int update_rule(struct firewall_rule *rule)
{
    struct rule_entry *entry;
    list_for_each_entry(entry, &rule_list, list) {
        if (entry->rule.rule_id == rule->rule_id) {
            unsigned int old_id = entry->rule.rule_id;
            memcpy(&entry->rule, rule, sizeof(*rule));
            entry->rule.rule_id = old_id;
            return 0;
        }
    }
    return -ENOENT;
}

static long firewall_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0, val;
    struct firewall_rule rule;
    struct firewall_rule_list rl;
    struct firewall_stats st;
    struct firewall_status status;
    struct rule_entry *entry;
    int idx;

    switch (cmd) {
    case CMD_SET_ENABLE:
        if (copy_from_user(&val, (int __user *)arg, sizeof(int))) return -EFAULT;
        enable_flag = val;
        if (val && !start_time) start_time = jiffies;
        if (!val) start_time = 0;
        break;
    case CMD_GET_STATUS:
        status.enabled = enable_flag;
        status.default_policy = default_policy;
        status.rule_count = rule_count;
        status.uptime_seconds = start_time ? jiffies_to_msecs(jiffies - start_time) / 1000 : 0;
        if (copy_to_user((void __user *)arg, &status, sizeof(status))) return -EFAULT;
        break;
    case CMD_ADD_RULE:
        if (copy_from_user(&rule, (void __user *)arg, sizeof(rule))) return -EFAULT;
        ret = add_rule(&rule) >= 0 ? 0 : ret;
        break;
    case CMD_DEL_RULE:
        if (copy_from_user(&val, (int __user *)arg, sizeof(int))) return -EFAULT;
        ret = del_rule(val);
        break;
    case CMD_UPDATE_RULE:
        if (copy_from_user(&rule, (void __user *)arg, sizeof(rule))) return -EFAULT;
        ret = update_rule(&rule);
        break;
    case CMD_LIST_RULES:
        memset(&rl, 0, sizeof(rl));
        idx = 0;
        list_for_each_entry(entry, &rule_list, list) {
            if (idx >= MAX_RULES) break;
            memcpy(&rl.rules[idx++], &entry->rule, sizeof(entry->rule));
        }
        rl.count = idx;
        if (copy_to_user((void __user *)arg, &rl, sizeof(rl))) return -EFAULT;
        break;
    case CMD_GET_STATS:
        st.total_checked = total_checked;
        st.total_dropped = total_dropped;
        st.total_accepted = total_accepted;
        memcpy(st.protocol_stats, protocol_stats, sizeof(protocol_stats));
        if (copy_to_user((void __user *)arg, &st, sizeof(st))) return -EFAULT;
        break;
    case CMD_SET_DEFAULT:
        if (copy_from_user(&val, (int __user *)arg, sizeof(int))) return -EFAULT;
        if (val == FW_DEFAULT_ACCEPT || val == FW_DEFAULT_DENY) default_policy = val;
        else ret = -EINVAL;
        break;
    case CMD_CLEAR_STATS:
        total_checked = total_dropped = total_accepted = 0;
        memset(protocol_stats, 0, sizeof(protocol_stats));
        list_for_each_entry(entry, &rule_list, list) entry->rule.hit_count = 0;
        break;
    case CMD_GET_RULE_COUNT:
        val = rule_count;
        if (copy_to_user((int __user *)arg, &val, sizeof(int))) return -EFAULT;
        break;
    default: ret = -EINVAL;
    }
    return ret;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = firewall_ioctl,
};

static int __init initmodule(void)
{
    int ret;
    myhook.hook = hook_func;
    myhook.hooknum = NF_INET_POST_ROUTING;
    myhook.pf = PF_INET;
    myhook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &myhook);
    ret = register_chrdev(major, DEVICE_NAME, &fops);
    if (ret < 0) {
        nf_unregister_net_hook(&init_net, &myhook);
        printk(KERN_ERR "firewall: register_chrdev failed\n");
        return ret;
    }
    if (major == 0) major = ret;
    printk(KERN_INFO "firewall: IPS module loaded, major=%d\n", major);
    return 0;
}

static void __exit cleanupmodule(void)
{
    struct rule_entry *entry, *tmp;
    nf_unregister_net_hook(&init_net, &myhook);
    unregister_chrdev(major, DEVICE_NAME);
    list_for_each_entry_safe(entry, tmp, &rule_list, list) { list_del(&entry->list); kfree(entry); }
    printk(KERN_INFO "firewall: IPS module unloaded\n");
}

module_init(initmodule);
module_exit(cleanupmodule);
