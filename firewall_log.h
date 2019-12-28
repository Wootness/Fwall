#ifndef _FW_LOGS_H_
#define _FW_LOGS_H_

#include "firewall_main.h"

// Log entry
typedef struct log_row_t{
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

// Log node for a linked list
typedef struct log_node_t{
    struct log_node_t *next;
	log_row_t *row;
} log_node_t;


// File-ops for log reader device
extern struct file_operations log_fops;

// The actual logs list
extern struct log_node_t *log_head_node;

// Manipulate logs list - Add a new entry to update the counter & timestamp of an old matching entry
// Parameters: time - Time stamp of the update
//             proto - protocol of IP payload of the recorded packet
//             src_ip - Source IP of the recorded packet
//             dst_ip - Destination IP of the recorded packet
//             src_port - Source Port of the recorded packet
//             dst_port - Destination Port of the recorded packet
//             reas - Reason which this packet was accepted/dropped
//             action - Whether the packet was accepted/dropped
int add_or_update_log_node(unsigned long time,
                           unsigned char proto,
                           __be32 src_ip,__be32 dst_ip,
                           __be16 src_port,__be16 dst_port,
                           reason_t reas,int action);
// Clears all logs in the list
void clear_logs_list(void);


#endif // _FW_LOGS_H_
