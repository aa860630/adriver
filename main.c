#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/slab.h>


#include "defs.h"


//DNS data: de b2 01 20 00 01 00 00 00 00 00 01 09 67 6f 6f 67 6c 65 61 64 73 01 67 0b 64 6f 75 62 6c 65 63 6c 69 63 6b 03 6e 65 74 0b 64 6c 69 6e 6b 72 6f 75 74 65 72 00 00 1c 00 01 00 00 29 04 b0 00 00
//googleads.g.doubleclick.net.dlinkrouter
static char *get_dns(unsigned char *data)
{
    // char *result = "";
    static char result[64];
    int start = 13;
    int num = (int)data[12];
    int i,index = 0;
    for(i = 0;i<64;i++)
        result[i] = '\0';
    while(num != 0)
    {
        for(i = 0; i < num; i++)
        {
            result[index] = data[start+i];
            index++;
        }
        start = start + num + 1;
        num = (int)data[start - 1];
    }
    printk(KERN_INFO "RESULT = %s",result);
    return result;
}


// decides if we should run GET sfilters on a packet
// currently, this implies
//   1. packet is TCP
//   2. TCP data starts with "GET "

//wei's TCP
static void should_run_get_sfilter(struct sk_buff *skb, struct buf *buf)
{
    struct iphdr *iph = (struct iphdr *)skb_network_header(skb);;
    struct tcphdr *tcp_header;
    unsigned char *payload;
    int payload_len;
    buf->data = NULL;

    if(!skb){
        return;
    }
    if (!iph || iph->protocol != IPPROTO_TCP) {
        printk(KERN_INFO "Not a TCP packet\n");
        return;
    }

    tcp_header = (struct tcphdr *) skb_transport_header(skb);
    if (!tcp_header) {
        printk(KERN_INFO "Failed to get TCP header\n");
        return;
    }


    if (tcp_header->syn) {
        printk(KERN_INFO "TCP control packet (SYN)\n");
        return;
    }
    if (tcp_header->rst) {
        printk(KERN_INFO "TCP control packet (RST)\n");
        return;
    }


    // int ip_hdr_len = iph->ihl * 4;
    // int tcp_hdr_len = tcph->doff * 4;
    int ip_hdr_len = sizeof(struct iphdr);
    int tcp_hdr_len = sizeof(struct tcphdr);
    int tcp_total_len = ntohs(iph->tot_len) - ip_hdr_len;

    printk(KERN_INFO "ip_hdr_len = %d", ip_hdr_len);
    printk(KERN_INFO "tcp_hdr_len = %d", tcp_hdr_len);
    printk(KERN_INFO "tcp_total_len = %d", tcp_total_len);
    
    if (tcp_total_len <= tcp_hdr_len) {
        printk(KERN_INFO "Invalid TCP length\n");
        return;
    }

    payload = (unsigned char *)((unsigned char *)tcp_header + tcp_hdr_len);
    payload_len = tcp_total_len - tcp_hdr_len;

    printk(KERN_INFO "Source port: %u\n", ntohs(tcp_header->source));
    printk(KERN_INFO "Destination port: %u\n", ntohs(tcp_header->dest));
    printk(KERN_INFO "payload = %*ph", payload_len, payload);

    return;


    // if (payload_len >= 4 && memcmp(payload, "GET ", 4) == 0) {
    //     printk(KERN_INFO "TCP data starts with GET\n");
    //     buf->data = kmalloc(payload_len, GFP_KERNEL);
    //     if (!buf->data) {
    //         printk(KERN_INFO "Memory allocation failed\n");
    //         return;
    //     }
    //     memcpy(buf->data, payload, payload_len);
    //     buf->should_free = 1;
        
    //     
    //     char *search_host = strnstr(payload, "Host: ", payload_len);
    //     if (search_host) {
    //         int remaining_len = payload_len - (search_host - (char *)payload);
    //         char *end_of_host = strnchr(search_host, remaining_len, '\n');
    //         if (end_of_host) {
    //             int host_len = end_of_host - search_host;
    //             char *host_field = kmalloc(host_len + 1, GFP_KERNEL); // +1 for null-terminator
    //             if (host_field) {
    //                 strncpy(host_field, search_host, host_len);
    //                 host_field[host_len] = '\0'; // null-terminate the string
    //                 printk(KERN_INFO "Host field: %s\n", host_field);
    //                 kfree(host_field);
    //             }
    //         }
    //     }
    // } else {
    //     buf->data = NULL;
    //     buf->should_free = 0;
    // }
}
    
// }
// decides if we should run dns sfilters on a packet
// this implies all UDP packets destined to port 53.
static void should_run_dns_sfilter(struct sk_buff *skb, struct buf *buf)
{
    size_t udp_off = 0;
    struct iphdr *ip_header = NULL;
    struct udphdr *udp_header = NULL;

    unsigned char *dns_data = NULL;
    size_t dns_data_len = 0;

    buf->data = NULL;


    if(!skb || !(ip_header = ip_hdr(skb)))
    {
        printk(KERN_INFO "Not IP");
        goto done;
    }
    if(IPPROTO_UDP != ip_header->protocol)
    {
        printk(KERN_INFO "Not UDP");
    }
    // get udp header
    udp_off = ip_header->ihl * 4;

    if (skb->len < udp_off + sizeof(struct udphdr)) {
        printk(KERN_ERR "Packet is too short to contain UDP header\n");
        goto done;
    }

    udp_header = udp_hdr(skb);
    if(!udp_header)
    {
        printk(KERN_INFO "Failed to get UDP header");
        goto done;
    }
    printk(KERN_INFO "port = %d", ntohs(udp_header->dest));

    if(ntohs(udp_header->dest) == 53)
    {
        dns_data = (unsigned char *)((unsigned char *)udp_header + sizeof(struct udphdr));
        dns_data_len = ntohs(udp_header->len) - sizeof(struct udphdr);
    }
    else
    {
        printk(KERN_INFO "not dport 53");
        goto done;
    }
    
    buf->data = NULL;
    buf->len = 0;
    buf->data = dns_data;
    buf->len = dns_data_len;

    buf->data = get_dns(dns_data);
    printk(KERN_INFO "buf data: %s", buf->data);
    printk(KERN_INFO "DNS filter matched");
    pr_debug("DNS filter matched\n");

done:
    ;
}



static unsigned int my_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
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
            // send_empty_html(skb, NF_INET_PRE_ROUTING);
            // send_reset_server(skb, NF_INET_PRE_ROUTING);
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
            // send_empty_html(skb, NF_INET_PRE_ROUTING);
            // send_reset_server(skb, NF_INET_PRE_ROUTING);
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
    // .owner = THIS_MODULE,
    .hook = my_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_BR_PRI_BRNF,
};


static int __net_init my_net_init(struct net *net)
{
    return nf_register_net_hook(net, &my_ops);
}

static void __net_exit my_net_exit(struct net *net)
{
    nf_unregister_net_hook(net, &my_ops);
}

static struct pernet_operations my_net_ops = {
    .init = my_net_init,
    .exit = my_net_exit,
};

static int __init mod_init(void)
{
    return register_pernet_device(&my_net_ops);
}

static void __exit mod_exit(void)
{
    unregister_pernet_device(&my_net_ops);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");