#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops *nfho_accept_in = NULL;
static struct nf_hook_ops *nfho_accept_out = NULL;
static struct nf_hook_ops *nfho_drop = NULL;

/* Simple function that accepts all packets */
unsigned int accept_packet_func(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
	printk(KERN_INFO "*** Packet Accepted ***\n");
    return NF_ACCEPT;
}

/* Simple function that rejects all packets */
unsigned int drop_packet_func(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
	printk(KERN_INFO "*** Packet Dropped ***\n");
    return NF_DROP;
}


static int __init hw1secws_init(void) {
    
    /* Define Accept input frames hook */
	nfho_accept_in = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_accept_in->hook 	    = (nf_hookfn*)accept_packet_func;
	nfho_accept_in->hooknum 	= NF_INET_LOCAL_IN;
	nfho_accept_in->pf 	    = PF_INET;
	nfho_accept_in->priority 	= NF_IP_PRI_FIRST;

    /* Define Accept output frames hook */
	nfho_accept_out = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_accept_out->hook 	    = (nf_hookfn*)accept_packet_func;
	nfho_accept_out->hooknum 	= NF_INET_LOCAL_OUT;
	nfho_accept_out->pf 	    = PF_INET;
	nfho_accept_out->priority 	= NF_IP_PRI_FIRST;

    /* Define Drop forwarding frames hook */
	nfho_drop = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_drop->hook 	    = (nf_hookfn*)drop_packet_func;
	nfho_drop->hooknum 	= NF_INET_FORWARD;
	nfho_drop->pf 	    = PF_INET;
	nfho_drop->priority 	= NF_IP_PRI_FIRST;
	
    /* Register hooks */
	nf_register_hook(nfho_accept_in);
	nf_register_hook(nfho_accept_out);
	nf_register_hook(nfho_drop);
    
    
	printk(KERN_INFO "hw1secws module registered!\n");
	return 0;
}
static void __exit hw1secws_exit(void) {
    
    /* Unregister hooks */
	nf_unregister_hook(nfho_accept_in);
	nf_unregister_hook(nfho_accept_out);
	nf_unregister_hook(nfho_drop);
    
    /* Free hook structs */
	kfree(nfho_accept_in);
	kfree(nfho_accept_out);
	kfree(nfho_drop);
    
	printk(KERN_INFO "hw1secws module removed!\n");
}
module_init(hw1secws_init);
module_exit(hw1secws_exit);