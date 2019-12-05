obj-m := firewall.o
firewall-objs := firewall_log.o  firewall_rules.o firewall_inspect.o fw.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
