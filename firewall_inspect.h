#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

// Inspects a packet and decides whether to accept or drop it
// Parameters:  hooknum - hook index where the packet was captured
//              skb - description of the packet as seen in the kernel
//              in - interface where the packet arrived from
//              out - interface where the packet should be delivered
//              okfn - ok function
unsigned int inspect_packet(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *));