#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

#include "defs.h"

// temporary
bool filter(unsigned char *data, size_t len)
{
    pr_alert("running filter, packet len %ld\n" ,len);
    hexdump(data, len);
    if (0x34 + 5 <= len && 0 == strncmp(data + 0x34, "hello", 5))
    {
        return true;
    }

    return false;
}

static unsigned int my_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
    const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct iphdr _ip, *ip = NULL;
    unsigned char *packet_data = NULL;
    size_t packet_len = 0;

    if (!skb)
    {
        goto ok;
    }

    // check for ip
    // (skb->data is IP now)
    ip = skb_header_pointer(skb, 0, sizeof(_ip), &_ip);
    if (!ip)
    {
        pr_alert("can't get ip\n");
        goto ok;
    }

    // check for tcp
    if (IPPROTO_TCP != ip->protocol)
    {
        pr_alert("ipproto != tcp, %d\n", ip->protocol);
        goto ok;
    }

    // TODO: this is not so efficient. meh :)
    if (skb_linearize(skb))
    {
        pr_alert("can't linearize!\n");
        goto ok; // not really, but nothing we can do
    }

    // linearized, so this is ok
    packet_len = skb->len;
    packet_data = skb->data;

    if (filter(packet_data, packet_len))
    {
        // bye
        pr_alert("filter ok\n");
        send_reset(skb, hooknum);
        return NF_DROP;
    }

    pr_alert("filter failed\n");

ok:
    return NF_ACCEPT;
}
static struct nf_hook_ops my_ops = {
    .hook = my_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT
};


static int mod_init(void)
{
    return nf_register_hook(&my_ops);
}

static void mod_exit(void)
{
    nf_unregister_hook(&my_ops);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");