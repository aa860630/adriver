#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

#include "defs.h"


// decides if we should run GET sfilters on a packet
// currently, this implies
//   1. packet is TCP
//   2. TCP data starts with "GET "
static char *should_run_get_sfilter(struct sk_buff *skb)
{
    // payload we read from each packet
    // large enough to contain whatever we'll extract from the packet
    // +1 for null term
    static char _data[MAX_GET_LINE_LEN + 1];

    struct iphdr _ip, *ip = NULL;
    size_t tcp_off = 0;
    struct tcphdr _tcp, *tcp = NULL;
    size_t data_off = 0;
    char *data = NULL;
    size_t data_len = 0;

    if (!skb)
    {
        pr_debug("skb is null\n");
        return NULL;
    }

    // check for ip
    // (skb->data is IP now)
    ip = skb_header_pointer(skb, 0, sizeof(_ip), &_ip);
    if (!ip)
    {
        pr_debug("can't get ip hdr\n");
        return NULL;
    }

    // check for tcp
    if (IPPROTO_TCP != ip->protocol)
    {
        pr_debug("ipproto != tcp, %d\n", ip->protocol);
        return NULL;
    }

    // get tcp header
    tcp_off = ip->ihl * 4;
    tcp = skb_header_pointer(skb, tcp_off, sizeof(_tcp), &_tcp);
    if (!tcp)
    {
        pr_debug("can't get tcp hdr\n");
        return NULL;
    }

    // reach to tcp data
    data_off = tcp_off + tcp->doff * 4;
    data = skb_header_pointer(skb, data_off, GET_PREFIX_LEN, _data);
    if (!data)
    {
        pr_debug("cant't get tcp data\n");
        return NULL;
    }
    if (0 != strncmp(data, GET_PREFIX, GET_PREFIX_LEN))
    {
        pr_debug("tcp payload is not GET\n");
        return NULL;
    }

    pr_debug("tcp data is GET!\n");

    // okay, now get the entire get line
    data_len = min_t(size_t, skb->len - data_off, MAX_GET_LINE_LEN);

    data = skb_header_pointer(skb, data_off, data_len, _data);
    // we want to null terminate it. if skb_header_pointer didn't copy (because this part
    // is linear), we'll do the copy ourself
    if (data != _data)
    {
        memcpy(_data, data, data_len);
        data = _data;
    }

    // null terminate it
    data[data_len] = '\0';

    pr_debug("get string: %s\n", data);

    return data;
}

static unsigned int my_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
    const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    unsigned char *get_line = NULL;

    get_line = should_run_sfilter(skb);
    if (!get_line)
    {
        // non-related packet
        return NF_ACCEPT;
    }

    pr_debug("running sfilter\n");
    if (run_get_sfilters(get_line))
    {
        // bye
        pr_debug("filter matched, dropping\n");
        send_reset(skb, hooknum);
        return NF_DROP;
    }

    // non-related get
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