#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#include "fw.h"
#include "firewall_log.h"


// Head of the linked list of log nodes
struct log_node_t *log_head_node = NULL;

static int log_row_size = sizeof(log_row_t);
static int log_row_node_size = sizeof(log_node_t);

/* Logs list iterator pointer */
static struct log_node_t *logs_iter_node = NULL;

/* Keeps track of how many bytes were sent from the log currently
 * stored at logs_iter_node. In this context 'next' is actually 'current'
 */
static int amount_read_from_iter;


// Checks if the values in given log_row match a set of given values:
// Parameters: row - row to check
//             proto - expected protocol number
//             src_ip - expected source IP
//             dst_ip - expected destination IP
//             src_port - expected source port
//             dst_port - expected destination port
//             dst_port - expected reason for logging
// Returns: 1 if equal, 0 otherwise
int check_log_vals(log_row_t *row, unsigned char proto,__be32 src_ip,__be32 dst_ip,__be16 src_port,__be16 dst_port,reason_t reas)
{
    return (row->src_ip == src_ip) &&
            (row->dst_ip == dst_ip) &&
            (row->src_port == src_port) &&
            (row->dst_port == dst_port) &&
            (row->protocol == proto) &&
            (row->reason == reas);
}

// Creates a new log row struct
// Parameters: time - timestamp of the logged event
//             proto - protocol number of the logged packet
//             src_ip - source IP of the logged packet
//             dst_ip - destination IP of the logged packet
//             src_port - source port of the logged packet
//             dst_port - destination port of the logged packet
//             dst_port - reason for logging the packet
// Returns: Pointer to the newly allocated log or NULL on failure
log_row_t *create_row(unsigned long time,unsigned char proto,__be32 src_ip,__be32 dst_ip,__be16 src_port,__be16 dst_port,reason_t reas,int action)
{
    log_row_t *out = NULL;
    out = (log_row_t *)kcalloc(1, log_row_size, GFP_ATOMIC);
    if(!out)
        return NULL;
    out->timestamp = time;
    out->protocol = proto;
    out->src_ip = src_ip;
    out->dst_ip = dst_ip;
    out->src_port = src_port;
    out->dst_port = dst_port;
    out->action = action;
    out->reason = reas;
    out->count = 1;
    return out;
}

// Deletes a log row
void delete_row(log_row_t *row)
{
    kfree(row);
}


/*** Logs List API ***/

/* Add a log row as a node in the linked list */
/* Returns: 1 if added, 2 if updated, 0 on failue*/
int add_or_update_log_node(unsigned long time,unsigned char proto,__be32 src_ip,__be32 dst_ip,__be16 src_port,__be16 dst_port,reason_t reas,int action)
{
    log_row_t *row;
    // For iterating existing nodes
    log_node_t *curr_node;
    log_node_t *next_node;
    // For new node if needed
    log_node_t *new_node;

    curr_node = log_head_node;
    while(curr_node != NULL) {
        if(check_log_vals(curr_node->row,proto, src_ip, dst_ip, src_port, dst_port, reas))
        {
            // Found a log matching the given parameters, updating counter + timestamp
            curr_node->row->count++;
            curr_node->row->timestamp = time;
            return 2;
        }

        // Advance to next node if no match
        next_node = curr_node->next;
        curr_node = next_node;
    }
    
    // No match - Decided to add.
    // allocating log struct and matching linked list node
    row = create_row(time,proto, src_ip, dst_ip, src_port, dst_port, reas,action);
    if(row == NULL) {
        return 0;
    }
    new_node = (log_node_t *)kcalloc(1,log_row_node_size, GFP_ATOMIC);
    if(new_node == NULL) {
        delete_row(row);
        return 0;
    }
    new_node->next = NULL;
    new_node->row = row;
    
    // Adding newly created node to linked list
    if(log_head_node != NULL)
    {
        // List no empty, link from our node to the last head
        new_node->next = log_head_node;
    }
    // Replace current head with our node
    log_head_node = new_node;

    return 1;
}

/* Clears the logs linked list,freeing any memory of nodes and rows */
void clear_logs_list(void)
{
    log_node_t *curr_node;
    log_node_t *next_node;
    
    curr_node = log_head_node;
    while(curr_node != NULL) {
        next_node = curr_node->next;
        delete_row(curr_node->row);
        kfree(curr_node);
        curr_node = next_node;
    }
    log_head_node = NULL;
}


/*** Logs char device API and management ***/

/* Custom open function  for file_operations */
int logs_dev_open(struct inode *_inode, struct file *_file) {
    logs_iter_node = log_head_node;
    amount_read_from_iter = 0;
    return 0;
}

/* Our custom read function  for file_operations */
ssize_t logs_dev_read(struct file *filp, char *buff, size_t length, loff_t *offp) {
    int left_in_next_node;
    int requested_length;
    int already_pushed_length;
    char* log_buff_start_ptr;
    
    requested_length = length;
    already_pushed_length = 0;
    

    if(logs_iter_node == NULL) {
        return 0;
    }
    
    while((requested_length > 0) && (logs_iter_node != NULL))
    {
        left_in_next_node = log_row_size - amount_read_from_iter;
        log_buff_start_ptr = ((char*)(logs_iter_node->row))+amount_read_from_iter;
        if(requested_length >= left_in_next_node)
        {
            /* Requested enough byes to atleast finish this node */
            /* Note that: index = amount last read from this node */
            if (copy_to_user(buff,log_buff_start_ptr ,left_in_next_node)) {
                return -EFAULT;
            }
            // Move to next node
            amount_read_from_iter = 0;
            logs_iter_node = logs_iter_node->next;
            // Update positions
            requested_length -= left_in_next_node;
            buff += left_in_next_node;
            already_pushed_length += left_in_next_node;
        }
        else {
            /* We were in the middle of a log, and user requested more bytes but not enough to finish this row*/
            if (copy_to_user(buff,log_buff_start_ptr,requested_length)) {
                return -EFAULT;
            }
            amount_read_from_iter += requested_length;
            already_pushed_length += requested_length;
            requested_length = 0;
        }
    }
    return already_pushed_length;
}

struct file_operations log_fops = {
    .owner = THIS_MODULE,
    .read = logs_dev_read,
    .open = logs_dev_open
};