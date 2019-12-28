#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/time.h>
#include "firewall_main.h"
#include "firewall_static_rules.h"
#include "firewall_manipulations.h"
#include "firewall_connections_table.h"
#include "firewall_ftp_data_conns.h"
#include "firewall_log.h"


#define RULE_CHECK_MATCHED 1
#define RULE_CHECK_MISMATCHED 0

// Chooses the next state for the connection, based on current state and a given packet
// only packets in the direction of the 4-tuple should be processed!
// Parameters: curr_state - current TCP state of the connection
//             tcp_header -  header form TCP of the currently proccessed packet
tcp_state_t move_tcp_state(tcp_state_t curr_state, struct tcphdr* tcp_header)
{
    switch (curr_state )
    {
        case TCP_STATE_SYN_SENT:
                // Only ack or psh-ack
                if(tcp_header->ack && !tcp_header->syn && !tcp_header->fin && !tcp_header->rst)
                    return TCP_STATE_ESTABLISHED;
                break;
        case TCP_STATE_SYN_RECV:
                // Only ack or psh-ack
                if(tcp_header->ack && !tcp_header->syn && !tcp_header->fin && !tcp_header->rst)
                    return TCP_STATE_ESTABLISHED;
                break;
        case TCP_STATE_ESTABLISHED:
                // Only ack or psh-ack
                if(tcp_header->ack && !tcp_header->syn && !tcp_header->fin && !tcp_header->rst)
                    return TCP_STATE_ESTABLISHED;
                // also fin-ack signals normal teardown
                if(tcp_header->ack && tcp_header->fin && !tcp_header->syn && !tcp_header->rst)
                    return TCP_STATE_FIN_SENT;
                break;
        case TCP_STATE_FIN_SENT:
                // Last ack - indicates final closing
                if(tcp_header->ack && !tcp_header->syn && !tcp_header->fin && !tcp_header->rst && !tcp_header->psh)
                    return TCP_STATE_CLOSED;
                break;
        case TCP_STATE_FIN_RECV:
                if(tcp_header->ack && !tcp_header->syn && !tcp_header->fin && !tcp_header->rst && !tcp_header->psh)
                    return TCP_STATE_CLOSED;
                break;
        case TCP_STATE_CLOSED:
                return TCP_STATE_CLOSED;
        case TCP_STATE_INVALID:
        default:
                 return TCP_STATE_INVALID;
    }
    return TCP_STATE_INVALID;
}


// Inspects a packet in the (dynamic) connection table and decides upon it - updates state
// if required and return verdict.
// Packet might be manipulated if part of an intercepted (MITM) connection
// Parameters: skb - SK buffer as received from the nethook
//             ip_header - Header of IP protocol from the packet
//             tcp_header - Header of TCP protocol from the packet
//             only_append_exist - Whether this packet should NOT start a new connection if one isn't found
//                                 (if it's a SYN packet)
// Returns: Either NF_DROP or NF_ACCEPT
int connection_table_inspect(struct sk_buff *skb,struct iphdr *ip_header, struct tcphdr* tcp_header, int only_append_existing)
{
    conn_table_entry_t* current_dir_entry = NULL;
    conn_table_entry_t* opposite_dir_entry = NULL;
    __be32 original_dest_ip;
    __be16 original_dest_port;

    find_matching_entries(ip_header->saddr,ip_header->daddr,
                            tcp_header->source,tcp_header->dest,
                            &current_dir_entry,&opposite_dir_entry);

    // Check for SYN packets
    if(tcp_header->syn && !tcp_header->ack) {

        // If this SYN is 'only_append_existing=True' it means it can't start new connections by itself
        // it must be accepted to a prematurely connnection prepared for it (Use case: FTP DATA Connections)
        if(only_append_existing) {
            // Searching in the sub-table of expecting connection
            pop_matching_ftp_entry(ip_header->saddr,ip_header->daddr,tcp_header->dest,&current_dir_entry);
            if(!current_dir_entry)
            {
                // Did not find a connection where this packet is expected, rejecting packet
                return NF_DROP;
            }

            // If we got here - we found the expecting connection!
            // Moving it to the main dynamic table

            // filling missing source port
            current_dir_entry->src_port = tcp_header->source;
            current_dir_entry->state = TCP_STATE_SYN_SENT;
            add_entry(current_dir_entry);

            return NF_ACCEPT;
        }
        else {
            // This is a normal new SYN packet which passed the static rules.
            if(current_dir_entry)
                return NF_DROP;

            current_dir_entry = (conn_table_entry_t *)kcalloc(1, sizeof(conn_table_entry_t), GFP_ATOMIC);
            if(!current_dir_entry){
                // Failed to allocate, we can't monitor this connection's state
                return NF_DROP;
            }
            current_dir_entry->src_ip = ip_header->saddr;
            current_dir_entry->dst_ip = ip_header->daddr;
            current_dir_entry->src_port = tcp_header->source;
            current_dir_entry->dst_port = tcp_header->dest;
            current_dir_entry->state = TCP_STATE_SYN_SENT;
            add_entry(current_dir_entry);

            // Manipulate packet if required
            original_dest_ip = ip_header->daddr;
            original_dest_port = tcp_header->dest;
            if(manipulate_preroute(skb,ip_header,tcp_header,current_dir_entry) == MANIP_RESULTS_MANIPULATED && !tcp_header->ack){
                // We make a note of the ports so our out-going traffic will be manipulated back
                // (Mainly the 'SYN-ACK' which is sent before userspace is even notified)
                add_manipulation_inst(ip_header->saddr,original_dest_ip, tcp_header->source, original_dest_port,NO_MANIPULATION_PORT);
                // If we manipulated, also register this new connection for Userspace to get
                register_awaiting_connection(ip_header->saddr,original_dest_ip, tcp_header->source, original_dest_port);
            }
            return NF_ACCEPT;
        }
    }

    // Checking for any packets with ACK=1 which might belong to a manipulated connection
    if(opposite_dir_entry && opposite_dir_entry->manipulation_port == tcp_header->dest 
                            && opposite_dir_entry->manipulation_port != NO_MANIPULATION_PORT) {
        // This is a packet from the server in our manipulated connection
        // manipulate it again and accept
        if(opposite_dir_entry->state == TCP_STATE_SYN_SENT) {
            // Our message is an indication that the connection became established
            opposite_dir_entry->state = TCP_STATE_ESTABLISHED;
        }
        manipulate_preroute(skb,ip_header,tcp_header,opposite_dir_entry);
        return NF_ACCEPT;
    }


    // Check for SYN-ACK
    if(tcp_header->syn && tcp_header->ack) {
        // If we got here, this SYN-ACK is NOT part of a manipulated connection.        
        if(current_dir_entry || !opposite_dir_entry) {
            // We are expecting the entry for the current direction to NOT exist and
            // the other direction to exist. If we got here at least one of those is false
            return NF_DROP;
        }
        
        if(opposite_dir_entry->state != TCP_STATE_SYN_SENT) { 
            // Other direction's state MUST be SYN_SENT
            return NF_DROP;
        }

        // First packet in this direction and we have seen a SYN on the opposite direction
        current_dir_entry = (conn_table_entry_t *)kcalloc(1, sizeof(conn_table_entry_t), GFP_ATOMIC);
        if(!current_dir_entry){
            // Failed to allocate, we can't monitor this connection's state
            return NF_DROP;
        }
        current_dir_entry->src_ip = ip_header->saddr;
        current_dir_entry->dst_ip = ip_header->daddr;
        current_dir_entry->src_port = tcp_header->source;
        current_dir_entry->dst_port = tcp_header->dest;
        current_dir_entry->state = TCP_STATE_SYN_RECV;
        add_entry(current_dir_entry);
        return NF_ACCEPT;
    }
    // Check for RST-ACK
    if(tcp_header->rst && tcp_header->ack) {
    
        if(!opposite_dir_entry) {
            // We are expecting at least the entry for the opposite direction to exist 
            // since some packet msut have triggered this RST. If it doesnt exist, we drop it
            return NF_DROP;
        }

        // The sending side is obviously not interested in this connection, so we remove opposite direction entry.
        // If an entry exists for the current direction, we remove it too
        remove_entry(opposite_dir_entry);
        kfree(opposite_dir_entry);
        if(current_dir_entry) {
            remove_entry(current_dir_entry);
            kfree(current_dir_entry);
        }

        // Since the opposite direction's entry exists, it's was valid in the static rules table
        // so it's only reasonable it should get it's response back. Hence the accept of this packet
        return NF_ACCEPT;
    }

    if(!current_dir_entry) {
        // No matching entry, dropping
        return NF_DROP;
    }

    // Updating state
    current_dir_entry->state = move_tcp_state(current_dir_entry->state,tcp_header);
    
    if(current_dir_entry->state == TCP_STATE_INVALID) {
        // Something broke in the protocol state machine, removing this connection
        remove_entry(current_dir_entry);
        kfree(current_dir_entry);
        if(opposite_dir_entry) {
            remove_entry(opposite_dir_entry);
            kfree(opposite_dir_entry);
        }
        return NF_DROP;
    }
 
    // Moved to a non-invalid TCP state, manipulate packet if required
    manipulate_preroute(skb,ip_header,tcp_header,current_dir_entry);

    // Check if we moved to ESTABLISH (ended synchronisation period)
    if(current_dir_entry->state == TCP_STATE_ESTABLISHED) {
        // If we just moved to ESTABLISHED, make sure the opposite conection changes 
        // from SYN_RECV to ESTABLISHED as well
        if(opposite_dir_entry && opposite_dir_entry->state == TCP_STATE_SYN_RECV) {
            opposite_dir_entry->state = TCP_STATE_ESTABLISHED;
        }
    }

    // Check if we shutting down, after 2 FIN-ACKs
    if(current_dir_entry->state == TCP_STATE_FIN_SENT) {
        if(opposite_dir_entry && opposite_dir_entry->state == TCP_STATE_FIN_SENT) {
            // Other side allready sent his FIN, Moving it to FIN RECV and removing *current* side
            opposite_dir_entry->state = TCP_STATE_FIN_RECV;
            remove_entry(current_dir_entry);
            kfree(current_dir_entry);
        }
        if(!opposite_dir_entry && current_dir_entry->manipulation_port != NO_MANIPULATION_PORT) {
            // This is a one-sided conversation with a manipulation port.
            // It represents a connection being manipulated by us.
            // The FIN-ACK here is the last message we expect to see in pre-route 
            // so we close the connection now
            remove_entry(current_dir_entry);
            kfree(current_dir_entry);
        }
    }
    
    // Check if the state is CLOSED
    if(current_dir_entry->state == TCP_STATE_CLOSED) {
        remove_entry(current_dir_entry);
        kfree(current_dir_entry);
        if(opposite_dir_entry) {
            remove_entry(opposite_dir_entry);
            kfree(opposite_dir_entry);
        }
    }

   return NF_ACCEPT;
}


int check_static_rule(rule_t *rule, direction_t dir, struct iphdr *ip_header, int proto, struct tcphdr* tcp_header, struct udphdr* udp_header)
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
    if(rule->dst_ip != 0) {
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


unsigned int inspect_preroute_packet(
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
        // Looking for any packet with ACK bit
        // those are checked against the dynamic rules table ONLY
        if(tcp_header->ack)
        {
            // Updating dynamic rules table
            return connection_table_inspect(skb,ip_header,tcp_header,1);
        }
        else if(tcp_header->syn)
        {
            
            // Checking SYN-only packets against the dynamic rule table as 'only append'.
            // This way if it's a SYN of prematurly prepared connection (for FTP DATA)
            // it will be accepted regardless of the static rules
            if(connection_table_inspect(skb,ip_header,tcp_header,1) == NF_ACCEPT)
            {
                return NF_ACCEPT;
            }
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
		rule_match = check_static_rule(curr_rule, dir, ip_header,proto,tcp_header,udp_header);
		
		if(rule_match == RULE_CHECK_MATCHED){
			add_or_update_log_node(stamp_seconds,proto,src_ip,dst_ip,src_port,dst_port,i,curr_rule->action);
            // Looking for ACCEPTed SYN packets
            if(curr_rule->action == NF_ACCEPT && tcp_header && (tcp_flag_word(tcp_header) & TCP_FLAG_SYN))
            {
                // Updating dynamic rules table
                return connection_table_inspect(skb,ip_header,tcp_header,0);
            }
			return curr_rule->action;
		}
	}

	// No matches in rules table, default action
	add_or_update_log_node(stamp_seconds,proto,src_ip,dst_ip,src_port,dst_port,REASON_NO_MATCHING_RULE,NF_DROP);
    return NF_DROP;
}

unsigned int inspect_local_out_packet(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;
	struct tcphdr* tcp_header = NULL;
    conn_table_entry_t* current_dir_entry = NULL;
    conn_table_entry_t* opposite_dir_entry = NULL;

    if(skb_is_nonlinear(skb))
            skb_linearize(skb);

	ip_header = ip_hdr(skb);
	if(ip_header->version != IP_VERSION)
		return NF_ACCEPT;

	/* Check for loopback traffic */
	if(IS_LOOPBACK_IP(ip_header->saddr) || IS_LOOPBACK_IP(ip_header->daddr))
		return NF_ACCEPT;
 

	if(ip_header->protocol == PROT_TCP) {
		tcp_header = (struct tcphdr *)(skb_network_header(skb)+(ip_header->ihl * 4));
        
        if(manipulate_output(skb,ip_header, tcp_header) == MANIP_RESULTS_MANIPULATED)
        {
            // This is packet in a manipulated connection. We need to inspect it's flags to
            // maintain right TCP connection state in the connections table

            find_matching_entries(ip_header->saddr,ip_header->daddr,
                                    tcp_header->source,tcp_header->dest,
                                    &current_dir_entry,&opposite_dir_entry);
            if(tcp_header->ack && !tcp_header->fin) {
                // Checking for 'Last ACK' in comming form out MITM program to the client
                if(opposite_dir_entry && opposite_dir_entry->state == TCP_STATE_FIN_SENT) {
                    remove_entry(opposite_dir_entry);
                    kfree(opposite_dir_entry);
                }
            }
        }
	}
    return NF_ACCEPT;
}
