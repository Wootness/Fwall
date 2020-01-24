#ifndef _FW_STATIC_RULES_H_
#define _FW_STATIC_RULES_H_

#include "firewall_main.h"

// static rule
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;


/* Init to NULLs */
extern rule_t rules_table[MAX_RULES];
extern char active_rules_count;
extern int rule_size;

#define RULES_UPDATE_SUCCESS 1
#define RULES_UPDATE_FAIL 0

// Updates the Rules Table with new rules
// Parameters: encoded_rules - encoded form of the new rules list
//            leng - amount of data in encoded_rules
// Returns: RULES_UPDATE_SUCCESS if successful, RULES_UPDATE_FAIL if failed to update
int update_rules_table(const char *encoded_rules,int leng);

#endif // _FW_STATIC_RULES_H_
