#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/string.h>
#include "firewall_main.h"
#include "firewall_ftp_data_conns.h"

// The list of expected FTP DATA connections
struct conn_table_entry_t *expected_ftp_data_conns = NULL;

// Search a matching expected connection.
// Note the absence of the 'src_port'. This is because those aren't known to us when registering
// the expected connections so we can't use them for searching
void pop_matching_ftp_entry(__be32 src_ip, __be32 dst_ip, __be16 dst_port, conn_table_entry_t** match)
{
    conn_table_entry_t* curr = expected_ftp_data_conns;
    conn_table_entry_t* prev = NULL;
   
    // Check for empty list
    if(curr == NULL)
        return;

    if(curr->src_ip == src_ip && curr->dst_ip == dst_ip &&
        curr->dst_port == dst_port)
    {
        
        // Special case: the HEAD of the list is the match
        *match = curr;
        expected_ftp_data_conns = expected_ftp_data_conns->next;
        return;
    }
    prev = curr;
    curr = curr->next;
    while(curr && (!*match)){
        if(curr->src_ip == src_ip && curr->dst_ip == dst_ip &&
            curr->dst_port == dst_port)
        {
            *match = curr;
            // re-linking the list without our match
            prev->next = curr->next;
            curr->next = NULL;
            return;
        }
        curr = curr->next;
	}
}

void push_ftp_entry(conn_table_entry_t* entry)
{
    // Setting as new list head
    entry->next = expected_ftp_data_conns;
    expected_ftp_data_conns = entry;
}

void reset_ftp_entries(void)
{
    conn_table_entry_t *curr_node;
    conn_table_entry_t *next_node;
    
    curr_node = expected_ftp_data_conns;
    expected_ftp_data_conns = NULL;
    while(curr_node != NULL) {
        next_node = curr_node->next;
        kfree(curr_node);
        curr_node = next_node;
    }
}
