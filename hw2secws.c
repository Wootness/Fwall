#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shai Shapira");

static int major_number;
static struct class* sysfs_firewall_class = NULL;
static struct device* sysfs_device = NULL;

static atomic_t sysfs_all_counter;
static atomic_t sysfs_accepted_counter;
static atomic_t sysfs_dropped_counter;


static struct nf_hook_ops *nfho_accept_in = NULL;
static struct nf_hook_ops *nfho_accept_out = NULL;
static struct nf_hook_ops *nfho_drop = NULL;

/* Simple function that accepts all packets */
unsigned int accept_packet_func(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
    atomic_inc(&sysfs_all_counter);
    atomic_inc(&sysfs_accepted_counter);
	printk(KERN_INFO "*** Packet Accepted ***\n");
    return NF_ACCEPT;
}

/* Simple function that rejects all packets */
unsigned int drop_packet_func(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
    atomic_inc(&sysfs_all_counter);
    atomic_inc(&sysfs_dropped_counter);
	printk(KERN_INFO "*** Packet Dropped ***\n");
    return NF_DROP;
}


static struct file_operations fops = {
	.owner = THIS_MODULE
};

ssize_t display_dropped_counter(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", atomic_read(&sysfs_dropped_counter));
}

ssize_t modify_dropped_counter(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1) {
        if(temp ==  0) {
            /* Only allowing to zero the counter */
            atomic_set(&sysfs_dropped_counter,temp);
        }
    }
	return count;	
}
ssize_t display_accepted_counter(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", atomic_read(&sysfs_accepted_counter));
}

ssize_t modify_accepted_counter(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1) {
        if(temp ==  0) {
            /* Only allowing to zero the counter */
            atomic_set(&sysfs_accepted_counter,temp);
        }
    }
	return count;	
}
ssize_t display_all_counter(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", atomic_read(&sysfs_all_counter));
}

ssize_t modify_all_counter(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1) {
        if(temp ==  0) {
            /* Only allowing to zero the counter */
            atomic_set(&sysfs_all_counter,temp);
        }
    }
	return count;	
}

static DEVICE_ATTR(dropped_packets, S_IRWXO , display_dropped_counter, modify_dropped_counter);
static DEVICE_ATTR(accepted_packets, S_IRWXO , display_accepted_counter, modify_accepted_counter);
static DEVICE_ATTR(all_packets, S_IRWXO , display_all_counter, modify_all_counter);

static void register_module_net_hooks(void){
    /* Define Accept input frames hook */
	nfho_accept_in = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_accept_in->hook 	    = (nf_hookfn*)accept_packet_func;
	nfho_accept_in->hooknum 	= NF_INET_LOCAL_IN;
	nfho_accept_in->pf 	    = PF_INET;
	nfho_accept_in->priority 	= NF_IP_PRI_FIRST;

    /* Define Accept output frames hook */
	nfho_accept_out = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_accept_out->hook 	    = (nf_hookfn*)accept_packet_func;
	nfho_accept_out->hooknum 	= NF_INET_LOCAL_OUT;
	nfho_accept_out->pf 	    = PF_INET;
	nfho_accept_out->priority 	= NF_IP_PRI_FIRST;

    /* Define Drop forwarding frames hook */
	nfho_drop = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_drop->hook 	    = (nf_hookfn*)drop_packet_func;
	nfho_drop->hooknum 	= NF_INET_FORWARD;
	nfho_drop->pf 	    = PF_INET;
	nfho_drop->priority 	= NF_IP_PRI_FIRST;
	
    /* Register hooks */
	nf_register_hook(nfho_accept_in);
	nf_register_hook(nfho_accept_out);
	nf_register_hook(nfho_drop);
}

static void unregister_module_net_hooks(void) {
/* Unregister hooks */
	nf_unregister_hook(nfho_accept_in);
	nf_unregister_hook(nfho_accept_out);
	nf_unregister_hook(nfho_drop);
    
    /* Free hook structs */
	kfree(nfho_accept_in);
	kfree(nfho_accept_out);
	kfree(nfho_drop);
}

static int __init hw2secws_init(void) {
    atomic_set(&sysfs_all_counter,0);
    atomic_set(&sysfs_accepted_counter,0);
    atomic_set(&sysfs_dropped_counter,0);
    register_module_net_hooks();
    
    //create char device
	major_number = register_chrdev(0, "firewall", &fops);\
	if (major_number < 0)
		return -1;
		
	//create sysfs class
	sysfs_firewall_class = class_create(THIS_MODULE, "firewall");
	if (IS_ERR(sysfs_firewall_class))
	{
		unregister_chrdev(major_number, "firewall_cdev");
        unregister_module_net_hooks();
		return -1;
	}
	
	//create sysfs device
	sysfs_device = device_create(sysfs_firewall_class, NULL, MKDEV(major_number, 0), NULL, "monitor");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_firewall_class);
		unregister_chrdev(major_number, "firewall_cdev");
        unregister_module_net_hooks();
		return -1;
	}
	//create sysfs file attributes
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_all_packets.attr))
	{
		device_destroy(sysfs_firewall_class, MKDEV(major_number, 0));
		class_destroy(sysfs_firewall_class);
		unregister_chrdev(major_number, "firewall_cdev");
        unregister_module_net_hooks();
		return -1;
	}
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_dropped_packets.attr))
	{
        device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_all_packets.attr);
		device_destroy(sysfs_firewall_class, MKDEV(major_number, 0));
		class_destroy(sysfs_firewall_class);
		unregister_chrdev(major_number, "firewall_cdev");
        unregister_module_net_hooks();
		return -1;
	}
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_accepted_packets.attr))
	{
        device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_all_packets.attr);
        device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_dropped_packets.attr);
		device_destroy(sysfs_firewall_class, MKDEV(major_number, 0));
		class_destroy(sysfs_firewall_class);
		unregister_chrdev(major_number, "firewall_cdev");
        unregister_module_net_hooks();
		return -1;
	}
	    
	printk(KERN_INFO "hw2secws module registered!\n");
	return 0;
}

static void __exit hw2secws_exit(void) {

    device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_all_packets.attr);
    device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_accepted_packets.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_dropped_packets.attr);
    device_destroy(sysfs_firewall_class, MKDEV(major_number, 0));
    class_destroy(sysfs_firewall_class);
    unregister_chrdev(major_number, "firewall_cdev");
    unregister_module_net_hooks();
    
	printk(KERN_INFO "hw2secws module removed!\n");
}
module_init(hw2secws_init);
module_exit(hw2secws_exit);