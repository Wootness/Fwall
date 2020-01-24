#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/types.h>
#include "firewall_main.h"
#include "firewall_inspect.h"
#include "firewall_log.h"
#include "firewall_static_rules.h"
#include "firewall_connections_table.h"
#include "firewall_manipulations.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shai Shapira");

static int major_number;
static struct class* firewall_class = NULL;
static struct device* sysfs_rules_device = NULL;
static struct device* sysfs_manipulations_device = NULL;
static struct device* sysfs_log_reset_device = NULL;
static struct device* sysfs_conns_device = NULL;
static struct device* chardev_log_device = NULL;


static struct nf_hook_ops *nfho_preroute_inspect = NULL;
static struct nf_hook_ops *nfho_localout_inspect = NULL;

/* return 0 on success, otherwise a non-zero error code.*/
static int register_module_net_hooks(void){
	int ret;
    /* Define Accept input frames hook */
	nfho_preroute_inspect = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(nfho_preroute_inspect == NULL)
	{
		/* Allocation failed */
		return -1;
	}
	nfho_preroute_inspect->hook 	    = (nf_hookfn*)inspect_preroute_packet;
	nfho_preroute_inspect->hooknum 		= NF_INET_PRE_ROUTING;
	nfho_preroute_inspect->pf 	    	= PF_INET;
	nfho_preroute_inspect->priority 	= NF_IP_PRI_FIRST;

    /* Register hooks */
	ret = nf_register_hook(nfho_preroute_inspect);
	if(ret != 0)
	{
		/* error when registering hook */
		kfree(nfho_preroute_inspect);
		return ret;
	}


    /* Define fix output frames hook */
	nfho_localout_inspect = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(nfho_localout_inspect == NULL)
	{
		/* Allocation failed */
		return -1;
	}
	nfho_localout_inspect->hook 	    = (nf_hookfn*)inspect_local_out_packet;
	nfho_localout_inspect->hooknum 		= NF_INET_LOCAL_OUT;
	nfho_localout_inspect->pf 	    	= PF_INET;
	nfho_localout_inspect->priority 	= NF_IP_PRI_FIRST;

    /* Register hooks */
	ret = nf_register_hook(nfho_localout_inspect);
	if(ret != 0)
	{
		/* error when registering hook, clearing last hook as well */
		nf_unregister_hook(nfho_preroute_inspect);
		kfree(nfho_preroute_inspect);
		kfree(nfho_localout_inspect);
		return ret;
	}
	return 0;
}

static void unregister_module_net_hooks(void) {
	/* Unregister hooks */
	nf_unregister_hook(nfho_preroute_inspect);
	nf_unregister_hook(nfho_localout_inspect);
    
    /* Free hook structs */
	kfree(nfho_preroute_inspect);
	kfree(nfho_localout_inspect);
}

ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf)
{
	int size = 0;
	// Writing first byte: amount of rules following
	buf[0] = active_rules_count;
	size ++;
	// Dumping all rules structs into the buffer
	memcpy(buf + size,(char*)rules_table, active_rules_count * rule_size);
	size += active_rules_count * rule_size;

	return size;
}

ssize_t display_conns(struct device *dev, struct device_attribute *attr, char *buf)
{
	conn_table_entry_t *export_iter_rule;
	int dyn_rule_actual_size;
	int size = 0;

	export_iter_rule = conn_table;

	// Size of actual data in rule
	dyn_rule_actual_size = sizeof(conn_table_entry_t) - sizeof(struct conn_table_entry_t *);
	
	// Dumping all entries' structs into the buffer
	while(export_iter_rule != NULL) {
		memcpy(buf + size,(char*)export_iter_rule, dyn_rule_actual_size);
		size += dyn_rule_actual_size;
		export_iter_rule = export_iter_rule->next;
    }

	return size;
}

ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int actual_size;
	// Make sure we have enough bytes for the magic word
	if(count < 2)
		return -EPERM;

	// Check magic word
	//	Buffer should start with 0x1234 before encoded rules
	if(buf[0] != 0x12 || buf[1] != 0x34)
		return -EPERM;

	actual_size = count - 2;
	if(update_rules_table(buf+2, actual_size) == RULES_UPDATE_FAIL)
		return -EPERM;

	// Rules updated, we need to reset active connections table
	reset_conns();
	reset_manipulations_list();
	reset_awaiting_manipulations_list();

	return count;	
}

ssize_t get_awaiting_manipulation(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	manipulation_inst_t* awaiting_con;
	printk(KERN_INFO "get_awaiting_manipulation Called!\n");
	awaiting_con = get_awaiting_connection();

	if(awaiting_con == NULL)
		return -EPERM;
	
	// Writing entire manipulation instruction to caller
	memcpy(buf,(char*)awaiting_con, sizeof(manipulation_inst_t));

	return sizeof(manipulation_inst_t);
}

ssize_t set_manipulation_command(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	__be32 client_ip,server_ip;
	__be16 client_port,server_port;
	__be16 manip_port;
	char command_type;
	int actual_size;
	int offset = 0;

	// Make sure we have enough bytes for the magic word
	if(count < 2)
		return -EPERM;

	// Check magic word
	//	Buffer should start with 0x5678 before encoded rules
	if(buf[0] != 0x56 || buf[1] != 0x78)
		return -EPERM;

	actual_size = count - 2;
	offset = 2;
	if(actual_size != 15)
		return -EPERM;

	command_type = buf[offset];
	offset++;
	
	// Copy IPs
	memcpy(&client_ip,buf + offset,4);
	offset += 4;
	memcpy(&server_ip,buf + offset,4);
	offset += 4;
	// Copy PORTs
	memcpy(&client_port,buf + offset,2);
	offset += 2;
	memcpy(&server_port,buf + offset,2);
	offset += 2;
	memcpy(&manip_port,buf + offset,2);

	if(command_type == MANIPULATION_CMD_INST) 
	{
		// We remove any existing instructions without manipulation port, 
		// Those are temporarly registered to allow establishing connection to client.
		remove_manipulation_inst(client_ip,server_ip,client_port,server_port,NO_MANIPULATION_PORT);

		// Registering the full instruction
		if(add_manipulation_inst(client_ip,server_ip,client_port,server_port,manip_port) == 0){
			// Memory error
			return -ENOMEM;
		}
		
		// Also set the manipulation port in the dynamic table
		set_entry_manip_port(client_ip,server_ip,client_port,server_port,manip_port);	
	}
	else
	{
		// Unexpected command type
		return -EPERM;
	}

	return count;	
}

ssize_t reset_logs(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	clear_logs_list();
	return count;	
}

static DEVICE_ATTR(rules, S_IRWXO , display_rules, modify_rules);
static DEVICE_ATTR(manipulations, S_IRWXO , get_awaiting_manipulation, set_manipulation_command);
static DEVICE_ATTR(reset, S_IWOTH , NULL, reset_logs);
static DEVICE_ATTR(conns, S_IROTH , display_conns, NULL);

static int __init hw5secws_init(void) {
    int err;

	printk(KERN_INFO "Starting to install hw5secws module...\n");

	err = register_module_net_hooks();
    if(err != 0)
		goto NET_HOOKS_FAIL;

    //create char device
	major_number = register_chrdev(0, CLASS_NAME, &log_fops);
	if (major_number < 0)
		goto FW_CHARDEV_FAIL;

	//create sysfs class
	firewall_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(firewall_class)) 
		goto SYSFS_CLASS_FAIL;
	
	// create sysfs device for rules update/read
	sysfs_rules_device = device_create(firewall_class, NULL, MKDEV(major_number, MINOR_RULES), NULL, DEVICE_NAME_RULES);	
	if (IS_ERR(sysfs_rules_device))
		goto RULES_DEV_FAIL;

	// create sysfs file attributes for rules
	if (device_create_file(sysfs_rules_device, (const struct device_attribute *)&dev_attr_rules.attr))
		goto RULES_FILE_FAIL;

	// create sysfs device for for logs reset
    sysfs_log_reset_device = device_create(firewall_class, NULL, MKDEV(major_number, MINOR_LOG_RESET), NULL, DEVICE_NAME_LOG);
    if (IS_ERR(chardev_log_device))
		goto LOG_RESET_DEV_FAIL;

	// create sysfs file attributes for logs reset
	if (device_create_file(sysfs_log_reset_device, (const struct device_attribute *)&dev_attr_reset.attr))
		goto LOG_RESET_FILE_FAIL;

	
	// create regular char device for logs reading
    chardev_log_device = device_create(firewall_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);
    if (IS_ERR(chardev_log_device))
		goto LOG_READER_DEV_FAIL;

	// create sysfs device for rules update/read
	sysfs_manipulations_device = device_create(firewall_class, NULL, MKDEV(major_number, MINOR_MANIP), NULL, DEVICE_NAME_MANIP);	
	if (IS_ERR(sysfs_manipulations_device))
		goto MANIP_DEV_FAIL;

	// create sysfs file attributes for rules
	if (device_create_file(sysfs_manipulations_device, (const struct device_attribute *)&dev_attr_manipulations.attr))
		goto MANIP_FILE_FAIL;


	// create sysfs device for for dynamic conns show
	sysfs_conns_device = device_create(firewall_class, NULL, MKDEV(major_number, MINOR_CONNS), NULL, DEVICE_NAME_CONNS);
    if (IS_ERR(sysfs_conns_device))
		goto CONNS_DEV_FAIL;

	// create sysfs file attributes for dynamic conns show
	if (device_create_file(sysfs_conns_device, (const struct device_attribute *)&dev_attr_conns.attr))
		goto CONNS_FILE_FAIL;

	printk(KERN_INFO "hw5secws module installed!\n");

	return 0;

	// Code to handle failures. Reaching a certain label will fall throu next labels
	// this way all resource allocated before failure point (and only them) will be released
CONNS_FILE_FAIL:
	device_destroy(firewall_class, MKDEV(major_number, MINOR_CONNS));
CONNS_DEV_FAIL:
	device_remove_file(sysfs_manipulations_device, (const struct device_attribute *)&dev_attr_manipulations.attr);
MANIP_FILE_FAIL:
	device_destroy(firewall_class, MKDEV(major_number, MINOR_MANIP));
MANIP_DEV_FAIL:
	device_destroy(firewall_class, MKDEV(major_number, MINOR_LOG));
LOG_READER_DEV_FAIL:
	device_remove_file(sysfs_log_reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
LOG_RESET_FILE_FAIL:
	device_destroy(firewall_class, MKDEV(major_number, MINOR_LOG_RESET));
LOG_RESET_DEV_FAIL:
	device_remove_file(sysfs_rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
RULES_FILE_FAIL:
	device_destroy(firewall_class, MKDEV(major_number, MINOR_RULES));
RULES_DEV_FAIL:
	class_destroy(firewall_class);
SYSFS_CLASS_FAIL:
	unregister_chrdev(major_number, CLASS_NAME);
FW_CHARDEV_FAIL:
	unregister_module_net_hooks();
NET_HOOKS_FAIL:
	return -1;
}

static void __exit hw5secws_exit(void) {
	// clear_logs_list();
	reset_conns();
	reset_manipulations_list();
	reset_awaiting_manipulations_list();
	device_remove_file(sysfs_conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
	device_destroy(firewall_class, MKDEV(major_number, MINOR_CONNS));
	device_remove_file(sysfs_manipulations_device, (const struct device_attribute *)&dev_attr_manipulations.attr);
	device_destroy(firewall_class, MKDEV(major_number, MINOR_MANIP));
	device_destroy(firewall_class, MKDEV(major_number, MINOR_LOG));
	device_remove_file(sysfs_log_reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
	device_destroy(firewall_class, MKDEV(major_number, MINOR_LOG_RESET));
	device_remove_file(sysfs_rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
	device_destroy(firewall_class, MKDEV(major_number, MINOR_RULES));
	class_destroy(firewall_class);
	unregister_chrdev(major_number, CLASS_NAME);
	unregister_module_net_hooks();

	printk(KERN_INFO "hw5secws module removed!\n");
}

module_init(hw5secws_init);
module_exit(hw5secws_exit);
