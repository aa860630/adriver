#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

#define _countof(a) (sizeof(a) / sizeof(a[0]))

#define IP(a,b,c,d) (((a)<<24)|((b)<<16)|((c)<<8)|(d))
static u32 blocked_ips[] = {
	IP(8,8,8,8),
};

static unsigned int my_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
	const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip = NULL;
	u32 dst_ip = 0;
	int i = 0;

	if (!skb)
	{
		goto ok;
	}

	ip = (struct iphdr*)skb_network_header(skb);
	if (!ip)
	{
		goto ok;
	}

	dst_ip = ntohl(ip->daddr);
	pr_debug("skb daddr %08x\n", dst_ip);

	for (i = 0; i < _countof(blocked_ips); ++i)
	{
		if (blocked_ips[i] == dst_ip)
		{
			pr_debug("dropping daddr %08x\n", dst_ip);
			return NF_DROP;
		}
	}

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