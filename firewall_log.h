#ifndef _FW_LOGS_H_
#define _FW_LOGS_H_

#include "fw.h"

// File-ops for log reader device
extern struct file_operations log_fops;

/* The actual logs list */
extern struct log_node_t *log_head_node;

// Manipulate logs list
int add_or_update_log_node(unsigned long time,
                           unsigned char proto,
                           __be32 src_ip,__be32 dst_ip,
                           __be16 src_port,__be16 dst_port,
                           reason_t reas,int action);
void clear_logs_list(void);


#endif // _FW_LOGS_H_
