#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/time.h>
#include "fw.h"
#include "firewall_rules.h"
#include "firewall_log.h"


#define RULE_CHECK_MATCHED 1
#define RULE_CHECK_MISMATCHED 0


int check_rule(rule_t *rule, direction_t dir, struct iphdr *ip_header, int proto, struct tcphdr* tcp_header, struct udphdr* udp_header)
{
    ushort temp_port = 0;

    if(!(rule->direction & dir)) {
        // Direction mistmatch
        return RULE_CHECK_MISMATCHED;
    }

    // Checking IPs
    // Check for limitation on srouce IP. 0 means 'any ip'
    if(rule->src_ip != 0) {
        if((rule->src_prefix_mask & ip_header->saddr) != (rule->src_prefix_mask & rule->src_ip)) { 
            return RULE_CHECK_MISMATCHED; // Mistmatching source ip subnet
        }
    }
    if(rule->src_ip != 0) {
        if((rule->dst_prefix_mask & ip_header->daddr) != (rule->dst_prefix_mask & rule->dst_ip)){
            return RULE_CHECK_MISMATCHED; // Mistmatching dest ip subnet
        }
    }
    // Check protocol
    if(rule->protocol != PROT_ANY) {
        if(rule->protocol == PROT_UDP && proto != PROT_UDP)
            return RULE_CHECK_MISMATCHED;
        if(rule->protocol == PROT_TCP && proto != PROT_TCP)
            return RULE_CHECK_MISMATCHED;
        if(rule->protocol == PROT_ICMP && proto != PROT_ICMP)
            return RULE_CHECK_MISMATCHED;
    }
    if(proto == PROT_TCP) {
        // Check if we have ports constraints
        if(rule->src_port != PORT_ANY) {
            if(rule->src_port == ABOVE_1023_INDICATOR_NETORD){
                temp_port = ntohs(tcp_header->source);
                if(temp_port <= 1023)
                    return RULE_CHECK_MISMATCHED;
            }
            else if(rule->src_port != tcp_header->source)
                return RULE_CHECK_MISMATCHED;
        }
        if(rule->dst_port != PORT_ANY) {
            if(rule->dst_port == ABOVE_1023_INDICATOR_NETORD){
                temp_port = ntohs(tcp_header->dest);
                if(temp_port <= 1023)
                    return RULE_CHECK_MISMATCHED;
            }
            else if(rule->dst_port != tcp_header->dest) {
                return RULE_CHECK_MISMATCHED;
            }
        }
        // Check Ack flag
        if(rule->ack != ACK_ANY) {
            if(rule->ack == ACK_YES && !tcp_header->ack)
                return RULE_CHECK_MISMATCHED;
            else if(rule->ack == ACK_NO && tcp_header->ack)
                return RULE_CHECK_MISMATCHED;
        }
    }
    else if(proto == PROT_UDP) {
        // Check if we have ports constraints
        if(rule->src_port != PORT_ANY) {
            if(rule->src_port == ABOVE_1023_INDICATOR_NETORD){
                temp_port = ntohs(udp_header->source);
                if(temp_port <= 1023)
                    return RULE_CHECK_MISMATCHED;
            }
            else if(rule->src_port != udp_header->source)
                return RULE_CHECK_MISMATCHED;
        }
        if(rule->dst_port != PORT_ANY) {
            if(rule->dst_port == ABOVE_1023_INDICATOR_NETORD){
                temp_port = ntohs(udp_header->source);
                if(temp_port <= 1023)
                    return RULE_CHECK_MISMATCHED;
            }
            else if(rule->dst_port != udp_header->dest)
                return RULE_CHECK_MISMATCHED;
        }
    }
    else if(proto == PROT_ICMP) {
        // Check if ports were defined. If so, ICMP isn't acceptable
        if(rule->src_port != PORT_ANY || rule->dst_port != PORT_ANY) {
            return RULE_CHECK_MISMATCHED;
        }
    }

    return RULE_CHECK_MATCHED;
}


unsigned int inspect_packet(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
	struct timespec stamp;
	unsigned long stamp_seconds;
	__be32 src_ip,dst_ip;
	__be16 src_port = 0;
	__be16 dst_port = 0;
	int i;
	int proto;
	rule_t *curr_rule;
	direction_t dir;
	int rule_match;
	struct iphdr *ip_header;
	struct tcphdr* tcp_header = NULL;
	struct udphdr* udp_header = NULL;

	if(strcmp(in->name,IN_NET_DEVICE_NAME) == 0)
		dir = DIRECTION_OUT;
	else if(strcmp(in->name,OUT_NET_DEVICE_NAME) == 0)
		dir = DIRECTION_IN;
	else // Not an interesting device
		return NF_ACCEPT; 

	ip_header = ip_hdr(skb);

	if(ip_header->version != IP_VERSION)
		return NF_ACCEPT;

	src_ip = ip_header->saddr;
	dst_ip = ip_header->daddr;

	/* Check for loopback traffic */
	if(IS_LOOPBACK_IP(src_ip) || IS_LOOPBACK_IP(dst_ip))
		return NF_ACCEPT;

	/* Get current time */
	getnstimeofday(&stamp);
	stamp_seconds = (unsigned long)stamp.tv_sec;

	proto = ip_header->protocol;
	if(proto == PROT_TCP) {
		tcp_header = (struct tcphdr *)(skb_network_header(skb)+(ip_header->ihl * 4));
		src_port = tcp_header->source;
		dst_port = tcp_header->dest;
		// Checking for x-mas packet
		if(tcp_header->fin && tcp_header->urg && tcp_header->psh) {
			add_or_update_log_node(stamp_seconds,proto,src_ip,dst_ip,src_port,dst_port,REASON_XMAS_PACKET,NF_DROP);
    		return NF_DROP;
		}
		
	}
	else if (proto == PROT_UDP) {
		udp_header = (struct udphdr *)(skb_network_header(skb)+(ip_header->ihl * 4));
		src_port = udp_header->source;
		dst_port = udp_header->dest;
	}
	else if (proto == PROT_ICMP) {
		// We allow rules about ICMP but we don't need to parse its header
	}
	else {
		// Any other protocol we immediatly accept
		return NF_ACCEPT;
	}
	
	for(i = 0 ;i<active_rules_count;i++) {
		curr_rule = rules_table + i;
		rule_match = check_rule(curr_rule, dir, ip_header,proto,tcp_header,udp_header);
		
		if(rule_match == RULE_CHECK_MATCHED){
			add_or_update_log_node(stamp_seconds,proto,src_ip,dst_ip,src_port,dst_port,i,curr_rule->action);
			return curr_rule->action;
		}
	}

	// No matches in rules table, default action
	add_or_update_log_node(stamp_seconds,proto,src_ip,dst_ip,src_port,dst_port,REASON_NO_MATCHING_RULE,NF_DROP);
    return NF_DROP;
}
