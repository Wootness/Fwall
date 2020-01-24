#ifndef _FW_MANIP_H_
#define _FW_MANIP_H_

#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/types.h>
#include "firewall_main.h"
#include "firewall_connections_table.h"

#define MANIP_RESULTS_UNTOUCHED 0
#define MANIP_RESULTS_MANIPULATED 1

// This module manages 2 lists:
//  * Manipulations list - Where information about which manipulations should be applied
//                         to out going packets is stored
//  * Awaiting manipulations requests list - Where information about new connection that
//                         should be manipulated is stored until USERSPACE asks for them
//                         (Entries are added when a SYN packet is seen on a HTTP/FTP port)


// Manipulation instructions
typedef struct manipulation_inst_t{
	__be32	client_ip;
	__be32	server_ip;
	__be16	client_port;
	__be16	server_port;
	__be16	manipulation_port;
	struct manipulation_inst_t *next;
} manipulation_inst_t;

/// Manipulations function

// Tries to manipulate a packet recieved in the NF_INET_PRE_ROUTING hook (Incoming from other PCs)
// Parameters: skb - skbuffer as created by the kernel
//             ip_header - IP header struct extracted from the packet
//             tcp_header - TCP header struct extracted from the packet
//             conn_table_entry_t - The connection table entry which this packet belongs to
//             direction - direction where the packet was recieved. Either DIRECTION_IN or DIRECTION_OUT is accepted
// Returns: Either MANIP_RESULTS_UNTOUCHED or MANIP_RESULTS_MANIPULATED
int manipulate_preroute(struct sk_buff *skb,struct iphdr *ip_header, struct tcphdr* tcp_header, conn_table_entry_t* matching_rule,int direction);
// Tries to manipulate a packet recieved in the NF_INET_LOCAL_OUT hook (Outgoing from the FW machine)
// Parameters: skb - skbuffer as created by the kernel
//             ip_header - IP header struct extracted from the packet
//             tcp_header - TCP header struct extracted from the packet
//             conn_table_entry_t - The connection table entry which this packet belongs to
// Returns: Either MANIP_RESULTS_UNTOUCHED or MANIP_RESULTS_MANIPULATED
int manipulate_output(struct sk_buff *skb,struct iphdr *ip_header, struct tcphdr* tcp_header);



/// Manage Manipulations Instructions list

// Adds a "Manipulation Instruction" to the list.
// Parameters: client_ip - IP of the client
//             server_ip - IP of the server
//             client_port - Port the client uses to speak to us
//             server_port - Port where we listen to the client and where the server listens to us
//             manipulation_port - Port we (the FW) uses to speak to the server
// Return 1 on success or 0 otherwise
int add_manipulation_inst(__be32 client_ip, __be32 server_ip, __be16 client_port,  __be16 server_port, __be16 manipulation_port);

// Removes a matching "Manipulation Instruction" from the list.
// Parameters: client_ip - IP of the client
//             server_ip - IP of the server
//             client_port - Port the client uses to speak to us
//             server_port - Port where we listen to the client and where the server listens to us
//             manipulation_port - Port we (the FW) uses to speak to the server
void remove_manipulation_inst(__be32 client_ip, __be32 server_ip, __be16 client_port,  __be16 server_port, __be16 manipulation_port);
// Resets the "Manipulation Instructions" list
void reset_manipulations_list(void);


/// Manage "Awaiting connections" info list

// Adds a "Awaiting Connection" indication to the list.
// Parameters: client_ip - IP of the client
//             server_ip - IP of the server
//             client_port - Source port where client tries to speak to the server
//             server_port - Destination port where the client tries to connect to the server
void register_awaiting_connection(__be32 client_ip, __be32 server_ip, __be16 client_port,  __be16 server_port );
// Tries to dequeue the next awaiting connection from the "Awaiting connections" list
// Returns: Next awaiting connection list or NULL if none is awaiting
manipulation_inst_t* get_awaiting_connection(void);
// Resets the "Awaiting Connection" list
void reset_awaiting_manipulations_list(void);


#endif // _FW_MANIP_H_