#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

#include "defs.h"


// decides if we should run GET sfilters on a packet
// currently, this implies
//   1. packet is TCP
//   2. TCP data starts with "GET "
static struct buf *should_run_get_sfilter(struct sk_buff *skb)
{
    // data we read from each packet
    // large enough to contain whatever we'll extract from the packet
    static char _data[MAX_GET_LINE_LEN];
    static struct buf last_buf;

    struct iphdr _ip, *ip = NULL;
    size_t tcp_off = 0;
    struct tcphdr _tcp, *tcp = NULL;
    size_t data_off = 0;
    char *data = NULL;
    size_t data_len = 0;

    last_buf.data = NULL;

    if (!skb)
    {
        pr_debug("skb is null\n");
        goto done;
    }

    // check for ip
    // (skb->data is IP now)
    ip = skb_header_pointer(skb, 0, sizeof(_ip), &_ip);
    if (!ip)
    {
        pr_debug("can't get ip hdr\n");
        goto done;
    }

    // check for tcp
    if (IPPROTO_TCP != ip->protocol)
    {
        pr_debug("ipproto != tcp, %d\n", ip->protocol);
        goto done;
    }

    // get tcp header
    tcp_off = ip->ihl * 4;
    tcp = skb_header_pointer(skb, tcp_off, sizeof(_tcp), &_tcp);
    if (!tcp)
    {
        pr_debug("can't get tcp hdr\n");
        goto done;
    }

    // reach to tcp data
    data_off = tcp_off + tcp->doff * 4;
    data = skb_header_pointer(skb, data_off, GET_PREFIX_LEN, _data);
    if (!data)
    {
        pr_debug("cant't get tcp data\n");
        goto done;
    }
    if (0 != strncmp(data, GET_PREFIX, GET_PREFIX_LEN))
    {
        pr_debug("tcp payload is not GET\n");
        goto done;
    }

    pr_debug("tcp data is GET!\n");

    // okay, now get the entire get line
    data_len = min_t(size_t, skb->len - data_off, MAX_GET_LINE_LEN);
    data = skb_header_pointer(skb, data_off, data_len, _data);

    last_buf.data = data;
    last_buf.len = data_len;

done:
    return &last_buf;
}

// decides if we should run dns sfilters on a packet
// this implies all UDP packets destined to port 53.
static struct buf *should_run_dns_sfilter(struct sk_buff *skb)
{
    // data we read from each packet.
    // large enough to contain whatever we'll extract from the packet
    static char _data[MAX_DNS_QUERY_LEN];
    static struct buf last_buf;

    struct iphdr _ip, *ip = NULL;
    size_t udp_off = 0;
    struct udphdr _udp, *udp = NULL;
    size_t data_off = 0;
    char *data = NULL;
    size_t data_len = 0;

    last_buf.data = NULL;

    if (!skb)
    {
        pr_debug("skb is null\n");
        goto done;
    }

    // check for ip
    // (skb->data is IP now)
    ip = skb_header_pointer(skb, 0, sizeof(_ip), &_ip);
    if (!ip)
    {
        pr_debug("can't get ip hdr\n");
        goto done;
    }

    // check for udp
    if (IPPROTO_UDP != ip->protocol)
    {
        pr_debug("ipproto != udp, %d\n", ip->protocol);
        goto done;
    }

    // get udp header
    udp_off = ip->ihl * 4;
    udp = skb_header_pointer(skb, udp_off, sizeof(_udp), &_udp);
    if (!udp)
    {
        pr_debug("can't get udp hdr\n");
        goto done;
    }
    if (53 != ntohs(udp->dest))
    {
        pr_debug("udp dport != 53, %d\n", ntohs(udp->dest));
        goto done;
    }

    // reach to udp data
    data_off = udp_off + sizeof(*udp);
    // probably the entire query
    data_len = min_t(size_t, skb->len - data_off, MAX_DNS_QUERY_LEN);
    data = skb_header_pointer(skb, data_off, data_len, _data);

    last_buf.data = data;
    last_buf.len = data_len;

done:
    return &last_buf;
}


static unsigned int my_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
    const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct buf *buf = NULL;

    buf = should_run_get_sfilter(skb);
    if (buf->data)
    {
        if (run_get_sfilters(buf))
        {
            // bye
            pr_debug("get filter matched, dropping\n");
            send_reset(skb, hooknum);
            return NF_DROP;
        }

        // optimization: not DNS for sure
        return NF_ACCEPT;
    }

    buf = should_run_dns_sfilter(skb);
    if (buf->data)
    {
        if (run_dns_sfilters(buf))
        {
            pr_debug("dns filter matched, dropping\n");
            // just drop here, don't REJECT
            return NF_DROP;
        }
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