obj-m := firewall.o
firewall-objs := firewall_log.o firewall_connections_table.o firewall_static_rules.o firewall_manipulations.o firewall_inspect.o firewall_main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
