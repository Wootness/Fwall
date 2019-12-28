#ifndef _FW_CONN_TABLE_H_
#define _FW_CONN_TABLE_H_

#include "firewall_main.h"

// This module manges the connection table for stateful inspection
// the connection table is implemented as a linke dlist of 'connetion entries'


// Connection table entry
// each entry is a node in a linked list
typedef struct conn_table_entry_t{
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port;
	__be16	dst_port;
	__be16	manipulation_port;  // Relevant only if this rule represents a manipulated connection,
                                // otherwise set to NO_MANIPULATION_PORT
	tcp_state_t state;
	struct conn_table_entry_t *next;
} conn_table_entry_t;

// Pointer to the connections table
extern struct conn_table_entry_t *conn_table;


// Finds an entry in the connections table, and it's matching opposite entry if found
// Parameters: src_ip - Source IP
//             dst_ip - Destination IP
//             src_port - Source port
//             dst_port - Destination port
//             current_direction - Pointer where the found entry will be placed
//             opposite_direction - Pointer where the found opposite entry will be placed, if found.
void find_matching_entries(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, conn_table_entry_t** current_direction, conn_table_entry_t** opposite_direction);

// Removes a connection to the connections table
// Parameters: to_remove - entry to remove from the table
void remove_entry(conn_table_entry_t* to_remove);

// Add a connection to the connections table
// Parameters: entry - entry to add to the table
void add_entry(conn_table_entry_t* entry);

// Reset connections table
void reset_conns(void);

// Specifies the 'Manipulation port' for a given connection
// Parameters: src_ip - source ip in the connection to edit
//             dst_ip - destination ip in the connection to edit
//             src_port - source port in the connection to edit
//             dst_port - destination port in the connection to edit
//             manip_port - manipulation port to add to the connection
// Returns: 1 on success, 0 otherwise
int set_entry_manip_port(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __be16 manip_port);

#endif // _FW_CONN_TABLE_H_
