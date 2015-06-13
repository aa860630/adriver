// Copied from net/ipv4/netfilter/ipt_REJECT.c

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter_ipv4.h>

/* Send RST reply */
void send_reset(struct sk_buff *oldskb, int hook)
{
    struct sk_buff *nskb;
    const struct iphdr *oiph;
    struct iphdr *niph;
    const struct tcphdr *oth;
    struct tcphdr _otcph, *tcph;

    /* IP header checks: fragment. */
    if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
        return;

    oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
                 sizeof(_otcph), &_otcph);
    if (oth == NULL)
        return;

    /* No RST for RST. */
    if (oth->rst)
        return;

    if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
        return;

    /* Check checksum */
    if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
        return;
    oiph = ip_hdr(oldskb);

    nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
             LL_MAX_HEADER, GFP_ATOMIC);
    if (!nskb)
        return;

    skb_reserve(nskb, LL_MAX_HEADER);

    skb_reset_network_header(nskb);
    niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
    niph->version    = 4;
    niph->ihl    = sizeof(struct iphdr) / 4;
    niph->tos    = 0;
    niph->id    = 0;
    niph->frag_off    = htons(IP_DF);
    niph->protocol    = IPPROTO_TCP;
    niph->check    = 0;
    niph->saddr    = oiph->daddr;
    niph->daddr    = oiph->saddr;

    skb_reset_transport_header(nskb);
    tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
    memset(tcph, 0, sizeof(*tcph));
    tcph->source    = oth->dest;
    tcph->dest    = oth->source;
    tcph->doff    = sizeof(struct tcphdr) / 4;

    if (oth->ack)
        tcph->seq = oth->ack_seq;
    else {
        tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
                      oldskb->len - ip_hdrlen(oldskb) -
                      (oth->doff << 2));
        tcph->ack = 1;
    }

    tcph->rst    = 1;
    tcph->check = ~tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
                    niph->daddr, 0);
    nskb->ip_summed = CHECKSUM_PARTIAL;
    nskb->csum_start = (unsigned char *)tcph - nskb->head;
    nskb->csum_offset = offsetof(struct tcphdr, check);

    /* ip_route_me_harder expects skb->dst to be set */
    skb_dst_set_noref(nskb, skb_dst(oldskb));

    nskb->protocol = htons(ETH_P_IP);
    if (ip_route_me_harder(nskb, RTN_UNSPEC))
        goto free_nskb;

    niph->ttl    = ip4_dst_hoplimit(skb_dst(nskb));

    /* "Never happens" */
    if (nskb->len > dst_mtu(skb_dst(nskb)))
        goto free_nskb;

    nf_ct_attach(nskb, oldskb);

    ip_local_out(nskb);
    return;

 free_nskb:
    kfree_skb(nskb);
}

void send_reset_server(struct sk_buff *oldskb, int hook)
{
    struct sk_buff *nskb;
    const struct iphdr *oiph;
    struct iphdr *niph;
    const struct tcphdr *oth;
    struct tcphdr _otcph, *tcph;

    /* IP header checks: fragment. */
    if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
        return;

    oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
                 sizeof(_otcph), &_otcph);
    if (oth == NULL)
        return;

    /* No RST for RST. */
    if (oth->rst)
        return;

    if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
        return;

    /* Check checksum */
    if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
        return;
    oiph = ip_hdr(oldskb);

    nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
             LL_MAX_HEADER, GFP_ATOMIC);
    if (!nskb)
        return;

    skb_reserve(nskb, LL_MAX_HEADER);

    skb_reset_network_header(nskb);
    niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
    niph->version    = 4;
    niph->ihl    = sizeof(struct iphdr) / 4;
    niph->tos    = 0;
    niph->id    = 0;
    niph->frag_off    = htons(IP_DF);
    niph->protocol    = IPPROTO_TCP;
    niph->check    = 0;
    niph->saddr    = oiph->saddr;
    niph->daddr    = oiph->daddr;

    skb_reset_transport_header(nskb);
    tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
    memset(tcph, 0, sizeof(*tcph));
    tcph->source    = oth->source;
    tcph->dest    = oth->dest;
    tcph->doff    = sizeof(struct tcphdr) / 4;

    tcph->seq = oth->seq;
    tcph->ack_seq = oth->ack_seq;
    tcph->ack = 1;

    tcph->rst    = 1;
    tcph->check = ~tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
                    niph->daddr, 0);
    nskb->ip_summed = CHECKSUM_PARTIAL;
    nskb->csum_start = (unsigned char *)tcph - nskb->head;
    nskb->csum_offset = offsetof(struct tcphdr, check);

    /* ip_route_me_harder expects skb->dst to be set */
    skb_dst_set_noref(nskb, skb_dst(oldskb));

    nskb->protocol = htons(ETH_P_IP);
    if (ip_route_me_harder(nskb, RTN_UNSPEC))
        goto free_nskb;

    niph->ttl    = ip4_dst_hoplimit(skb_dst(nskb));

    /* "Never happens" */
    if (nskb->len > dst_mtu(skb_dst(nskb)))
        goto free_nskb;

    nf_ct_attach(nskb, oldskb);

    ip_local_out(nskb);
    return;

 free_nskb:
    kfree_skb(nskb);
}
