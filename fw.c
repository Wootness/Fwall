#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/types.h>
#include "fw.h"
#include "firewall_inspect.h"
#include "firewall_log.h"
#include "firewall_rules.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shai Shapira");

static int major_number;
static struct class* firewall_class = NULL;
static struct device* sysfs_rules_device = NULL;
static struct device* sysfs_log_reset_device = NULL;
static struct device* chardev_log_device = NULL;

static struct nf_hook_ops *nfho_inspect = NULL;

/* return 0 on success, otherwise a non-zero error code.*/
static int register_module_net_hooks(void){
	int ret;
    /* Define Accept input frames hook */
	nfho_inspect = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(nfho_inspect == NULL)
	{
		/* Allocationg failed */
		return -1;
	}
	nfho_inspect->hook 	    = (nf_hookfn*)inspect_packet;
	nfho_inspect->hooknum 	= NF_INET_FORWARD;
	nfho_inspect->pf 	    = PF_INET;
	nfho_inspect->priority 	= NF_IP_PRI_FIRST;

    /* Register hooks */
	ret = nf_register_hook(nfho_inspect);
	if(ret != 0)
	{
		/* error when registering hook */
		kfree(nfho_inspect);
		return ret;
	}
	return 0;
}

static void unregister_module_net_hooks(void) {
	/* Unregister hooks */
	nf_unregister_hook(nfho_inspect);
    
    /* Free hook structs */
	kfree(nfho_inspect);
}

ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
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
	return count;	
}

ssize_t reset_logs(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	clear_logs_list();
	return count;	
}

static DEVICE_ATTR(rules, S_IRWXO , display_rules, modify_rules);
static DEVICE_ATTR(reset, S_IWOTH , NULL, reset_logs);

static int __init hw3secws_init(void) {
    int err;
	
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

	printk(KERN_INFO "hw3secws module installed!\n");

	return 0;

	// Code to handle failures. Reaching a certain label will fall throu next labels
	// this way all resource allocated before failure point (and only them) will be released
LOG_READER_DEV_FAIL:
	device_remove_file(sysfs_log_reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
LOG_RESET_FILE_FAIL:
	device_destroy(firewall_class, MKDEV(major_number, MINOR_LOG_RESET));
LOG_RESET_DEV_FAIL:
	device_remove_file(sysfs_rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
RULES_DEV_FAIL:
	device_destroy(firewall_class, MKDEV(major_number, MINOR_RULES));
RULES_FILE_FAIL:
	class_destroy(firewall_class);
SYSFS_CLASS_FAIL:
	unregister_chrdev(major_number, CLASS_NAME);
FW_CHARDEV_FAIL:
	unregister_module_net_hooks();
NET_HOOKS_FAIL:
	return -1;
}

static void __exit hw3secws_exit(void) {
	clear_logs_list();
	device_destroy(firewall_class, MKDEV(major_number, MINOR_LOG));
	device_remove_file(sysfs_log_reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
	device_destroy(firewall_class, MKDEV(major_number, MINOR_LOG_RESET));
	device_remove_file(sysfs_rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
	device_destroy(firewall_class, MKDEV(major_number, MINOR_RULES));
	class_destroy(firewall_class);
	unregister_chrdev(major_number, CLASS_NAME);
	unregister_module_net_hooks();

	printk(KERN_INFO "hw3secws module removed!\n");
}

module_init(hw3secws_init);
module_exit(hw3secws_exit);
