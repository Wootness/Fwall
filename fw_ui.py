class_name = 'firewall'
device_name = 'monitor'
all_attr_name = 'all_packets'
drop_attr_name = 'dropped_packets'
accp_attr_name = 'accepted_packets'


def main(argv):
	if(len(argv) > 2 or (len(argv) == 2 and argv[1] != '0')):
		print('USAGE {0} [0]\n\t0 - (optional) resets firewall counters\n'.format(argv[0]))
		return (-1)
	if(len(argv) == 2 and argv[1] == '0'):
		# Reset requested
		file_accp = open('/sys/class/{0}/{1}/{2}'.format(class_name,device_name,accp_attr_name),'w')
		file_accp.write('0')
		file_accp.close();
		file_drop = open('/sys/class/{0}/{1}/{2}'.format(class_name,device_name,drop_attr_name),'w')
		file_drop.write('0')
		file_drop.close();
		file_all = open('/sys/class/{0}/{1}/{2}'.format(class_name,device_name,all_attr_name),'w')
		file_all.write('0')
		file_all.close();
		return 0
	elif (len(argv) == 1):
		# Status print requested
		print('Firewall Packets Summary:')
		file_accp = open('/sys/class/{0}/{1}/{2}'.format(class_name,device_name,accp_attr_name),'r')
		print('Number of accepted packets: {0}'.format(file_accp.readline())[:-1])
		file_accp.close();
		file_drop = open('/sys/class/{0}/{1}/{2}'.format(class_name,device_name,drop_attr_name),'r')
		print('Number of dropped packets: {0}'.format(file_drop.readline())[:-1])
		file_drop.close();
		file_all = open('/sys/class/{0}/{1}/{2}'.format(class_name,device_name,all_attr_name),'r')
		print('Total number of packets: {0}'.format(file_all.readline())[:-1])
		file_all.close();
		return 0
	return (-1)

if __name__ == '__main__':
	import sys
	sys.exit(main(sys.argv))
