#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/string.h>
#include "firewall_main.h"
#include "firewall_connections_table.h"
#include "firewall_manipulations.h"

// The connection table, as a linked list
struct conn_table_entry_t *conn_table = NULL;


void find_matching_entries(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, conn_table_entry_t** current_direction, conn_table_entry_t** opposite_direction)
{
    conn_table_entry_t* curr = conn_table;
   
    // Check for empty list
    if(curr == NULL)
        return;

    // Keep searching linked list in the node until end or both curr/opposite directions found
    while(curr && (!*current_direction || !*opposite_direction)){
        // Checking if 'correct' way of 4-tuple
        if(curr->src_ip == src_ip && curr->dst_ip == dst_ip &&
            curr->src_port == src_port && curr->dst_port == dst_port)
        {
            *current_direction = curr;
        }
        // Checking for 'opposite'/'reverse' way of 4-tuple
        if(curr->dst_ip == src_ip && curr->src_ip == dst_ip &&
            curr->dst_port == src_port && (curr->src_port == dst_port || curr->manipulation_port == dst_port)) 
        {
            *opposite_direction = curr;
        }
        curr = curr->next;
	}
}

void remove_entry(conn_table_entry_t* to_remove)
{
    conn_table_entry_t* curr = conn_table;
    
    // Check for empty list
    if(curr == NULL)
        return;

    if(curr == to_remove) {
        // Special case: removing the head
        conn_table = to_remove->next;
        return;
    }
    else {
        // Keep searching linked list in the node until end or both curr/opposite directions found
        while(curr){
           if(curr->next == to_remove)
           {
               // Re-linking the list without our item
               curr->next = to_remove->next;
               return;
           }
           curr = curr->next; 
        }
    } 
}

void add_entry(conn_table_entry_t* entry)
{
    // Setting as new list head
    entry->next = conn_table;
    conn_table = entry;
    return;
}

/* Clears the connections linked list,freeing any memory of nodes */
void reset_conns(void)
{
    conn_table_entry_t *curr_node;
    conn_table_entry_t *next_node;
    
    curr_node = conn_table;
    conn_table = NULL;
    while(curr_node != NULL) {
        next_node = curr_node->next;
        kfree(curr_node);
        curr_node = next_node;
    }
}

int set_entry_manip_port(__be32 client_ip, __be32 server_ip, __be16 client_port, __be16 server_port, __be16 manip_port)
{
    conn_table_entry_t* current_dir_entry = NULL;
    conn_table_entry_t* opposite_dir_entry = NULL;

    find_matching_entries(client_ip,server_ip,client_port,server_port,
                                    &current_dir_entry,&opposite_dir_entry);

    if(!current_dir_entry && !opposite_dir_entry) {
        return 0;
    }

   if(current_dir_entry)
        current_dir_entry->manipulation_port = manip_port;
        
   if(opposite_dir_entry)
        opposite_dir_entry->manipulation_port = manip_port;

   return 1;
}