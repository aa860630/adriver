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

// this is like skb_header_pointer, but only allocates if required,
// because I don't wanna do that before knowing whether it's linear
static void *my_skb_header_pointer(struct sk_buff *skb, size_t data_off, size_t data_len, bool *should_free)
{
    char *data = NULL;

    *should_free = false;

    if (skb_headlen(skb) >= data_off + data_len)
    {
        return skb->data + data_off;
    }
    else
    {
        data = kmalloc(data_len, GFP_KERNEL);
        if (!data)
        {
            return NULL;
        }

        if (skb_copy_bits(skb, data_off, data, data_len) < 0)
        {
            kfree(data);
            return NULL;
        }
        *should_free = true;

        return data;
    }
}

// decides if we should run GET sfilters on a packet
// currently, this implies
//   1. packet is TCP
//   2. TCP data starts with "GET "
static void should_run_get_sfilter(struct sk_buff *skb, struct buf *buf)
{
    struct iphdr _ip, *ip = NULL;
    size_t tcp_off = 0;
    struct tcphdr _tcp, *tcp = NULL;
    size_t data_off = 0;
    char get_buf[GET_PREFIX_LEN];
    char *data = NULL;
    size_t data_len = 0;

    buf->data = NULL;

    // (skb->data is @ IP)
    if (!skb || !(ip = skb_header_pointer(skb, 0, sizeof(_ip), &_ip)) || IPPROTO_TCP != ip->protocol)
    {
        goto done; // not ip - tcp
    }

    tcp_off = ip->ihl * 4;
    if (!(tcp = skb_header_pointer(skb, tcp_off, sizeof(_tcp), &_tcp)) || ntohs(80) != tcp->dest)
    {
        goto done; // bad tcp or not dport 80
    }

    // reach to tcp data
    data_off = tcp_off + tcp->doff * 4;
    if (!(skb_header_pointer(skb, data_off, sizeof(get_buf), get_buf))
        || 0 != strncmp(data, GET_PREFIX, GET_PREFIX_LEN))
    {
        goto done; // not GET
    }

    // okay, now get some of the GET params (specifically the query string and host field
    // which convey instersting data)
    data_len = min_t(size_t, skb->len - data_off, MAX_GET_PARAMS_LEN);

    data = my_skb_header_pointer(skb, data_off, data_len, &buf->should_free);

    buf->data = data;
    buf->len = data_len;

done:
    ;
}

// decides if we should run dns sfilters on a packet
// this implies all UDP packets destined to port 53.
static void should_run_dns_sfilter(struct sk_buff *skb, struct buf *buf)
{
    struct iphdr _ip, *ip = NULL;
    size_t udp_off = 0;
    struct udphdr _udp, *udp = NULL;
    size_t data_off = 0;
    char *data = NULL;
    size_t data_len = 0;

    buf->data = NULL;

    // (skb->data is @ IP)
    if (!skb || !(ip = skb_header_pointer(skb, 0, sizeof(_ip), &_ip)) || IPPROTO_UDP != ip->protocol)
    {
        goto done; // not ip - udp
    }

    // get udp header
    udp_off = ip->ihl * 4;
    if (!(udp = skb_header_pointer(skb, udp_off, sizeof(_udp), &_udp)) || 53 != ntohs(udp->dest))
    {
        goto done; // bad udp or not dport 53
    }

    // reach to udp data
    data_off = udp_off + sizeof(*udp);
    // probably the entire query
    data_len = min_t(size_t, skb->len - data_off, MAX_DNS_QUERY_LEN);

    data = my_skb_header_pointer(skb, data_off, data_len, &buf->should_free);

    buf->data = data;
    buf->len = data_len;

done:
    ;
}


static unsigned int my_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
    const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    int ret = NF_ACCEPT;
    struct buf buf;

    should_run_get_sfilter(skb, &buf);
    if (buf.data)
    {
        if (run_get_sfilters(&buf))
        {
            // bye
            pr_debug("get filter matched, dropping\n");
            send_reset(skb, hooknum);
            ret = NF_DROP;
            goto done;
        }

        // optimization: not DNS for sure
        ret = NF_ACCEPT;
        goto done;
    }
    // buf.data is NULL, no need to free

    should_run_dns_sfilter(skb, &buf);
    if (buf.data)
    {
        if (run_dns_sfilters(&buf))
        {
            pr_debug("dns filter matched, dropping\n");
            // just drop here, don't REJECT
            ret = NF_DROP;
            goto done;
        }
    }

done:
    if (buf.data && buf.should_free)
    {
        kfree(buf.data);
    }
    return ret;
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