#ifndef _FW_FTP_RULES_H_
#define _FW_FTP_RULES_H_

#include "firewall_main.h"
#include "firewall_connections_table.h"

// This module is responsible for managing EXPECTED FTP data connections info
// So when a 4-tuple entry is registered from userspace as 'a FTP connection will soon open here'
// it is saved in this module until claimed by the SYN packet of the connection


// Finds an entry in the expected FTP DATA connections list. If found, it's removed from the list
// Parameters: src_ip - Source IP
//             dst_ip - Destination IP
//             dst_port - Destination port
//             match - Pointer where the found entry will be placed
void pop_matching_ftp_entry(__be32 src_ip, __be32 dst_ip, __be16 dst_port, conn_table_entry_t** match);

// Adds an expected FTP DATA connection entry to the list.
// Parameters: entry - The entry to add to the list
void push_ftp_entry(conn_table_entry_t* entry);

// Resets the 'expecting FTP connection' list and freeing entries
void reset_ftp_entries(void);

#endif // _FW_FTP_RULES_H_
