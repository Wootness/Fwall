import resource
import struct
import socket
import datetime as dt
import os.path as path

class_name = 'fw'
device_name = 'rules'
rules_attr_name = 'rules'
logs_device_name = 'log'
reset_attr_name = 'reset'
logs_char_device_name = 'fw_log'

dir_strs = {
	1:'in',
	2:'out',
	3:'any',
}
action_strs = {
	0:'drop',
	1:'accept'
}
reason_strs = {
	-1:'REASON_FW_INACTIVE',
	-2:'REASON_NO_MATCHING_RULE',
	-4:'REASON_XMAS_PACKET',
	-6:'REASON_ILLEGAL_VALUE',
}
proto_strs = {
	1:'icmp',
	6:'tcp',
	17:'udp',
	255:'other',
	143:'any'
}
port_strs = {
	0:'any',
	1024:'>1023',
}
ack_strs = {
	1:'no',
	2:'yes',
	3:'any',
}

# Constants
page_size = resource.getpagesize()
max_rules = 50
rule_name_size = 20
rule_size = 60
log_size = 28
NF_IP_FORWARD = 2

# Helper method to turn an integer into an IPv4 address strings and vice versa
# Taken from: https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]
def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

# Helper method to reverse search a dictionary
def get_key_by_val(dictionary,val):
	if val in dictionary.values():
		return list(dictionary.keys())[list(dictionary.values()).index(val)], True
	return val, False

# Helper method to parse ip addres (or 'any') to IP,mask, CIDR number (/k)
def parse_ip_addr(text):
	if(text == 'any'):
		return (0,0,0)
	else:
		src_ip, cidr = text.split('/')
		split = src_ip.split('.')
		if(len(split) != 4):
			raise Exception('Not enough number in IP address')
		src_ip = ip2int(src_ip)
		cidr = int(cidr)
		if(cidr < 0 or cidr > 32):
			raise Exception('CIDR number out of range')
		src_mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
		return (src_ip,src_mask,cidr)

def load_rules(path):
	final = '\x12\x34'
	with open(path,'r') as new_rules_file:
		i = 0
 		for line in new_rules_file.readlines():
			if(line.count(' ') != 8):
				print('Cannot load rule at line \'{0}\', Bad format - expected 9 values with single space between every pair'.format(i))
				return
			_, direction, src_addr, dst_addr, proto, src_port, dst_port, ack, action = (line.lower().rstrip().split(' '))
			name = line.split(' ')[0]
			if(len(name) > rule_name_size):
				print('Cannot load rule at line \'{0}\', name too long (max: {1} characters)'.format(i,rule_name_size))
				return
			direction, found = get_key_by_val(dir_strs,direction)
			if not found:
				print('Cannot load rule at line \'{0}\', Invalid direction value'.format(i))
				return
			proto, found = get_key_by_val(proto_strs,proto)
			if not found:
				print('Cannot load rule at line \'{0}\', Invalid protocol value'.format(i))
				return
			src_port = int(get_key_by_val(port_strs,src_port)[0])
			dst_port = int(get_key_by_val(port_strs,dst_port)[0])
			ack, found  = get_key_by_val(ack_strs,ack)
			if not found:
				print('Cannot load rule at line \'{0}\', Invalid ACK bit value'.format(i))
				return
			action, found = get_key_by_val(action_strs,action)
			if not found:
				print('Cannot load rule at line \'{0}\', Invalid action value'.format(i))
				return
			try:
				src_ip,src_mask,src_k = parse_ip_addr(src_addr)
			except Exception as e:
				print('Cannot load rule at line \'{0}\',Failed to parse source IP address. Error: {0}'.format(i,e))
				return
			try:
				dst_ip,dst_mask,dst_k = parse_ip_addr(dst_addr)
			except Exception as e:
				print('Cannot load rule at line \'{0}\',Failed to parse destination IP address. Error: {0}'.format(i,e))
				return
			packed = struct.pack('>BIIBIIBhhBBB',direction,src_ip,src_mask,src_k,dst_ip,dst_mask,dst_k,src_port,dst_port,proto,ack,action)
			# Padding name to right size
			name = name.ljust(rule_name_size,'\0')
			# Combining all encoded parts of the current rule with previous rules
			final = final + name  + packed
			i += 1
	new_rules_file.close()
	if(len(final) <= 2):
		print('Cannot load rules, No rules found in file.')
		return
	
	if(i>max_rules):
		print('Cannot load rules, Too many rules provided (Max: 50).')
		return
	
	# Opening the sysfs device and writing the encoded data into it
	file_rules = open('/sys/class/{0}/{1}/{2}'.format(class_name,device_name,rules_attr_name),'w')
	file_rules.write(final)
	file_rules.close()
	

def show_rules():
	file_rules = open('/sys/class/{0}/{1}/{2}'.format(class_name,device_name,rules_attr_name),'r')
	num_rules_raw = file_rules.read(1)
	# Read number of rules in output - found in first byte
	num_rules = struct.unpack('B',num_rules_raw)[0]
	
	for i in xrange(num_rules):
		# Get all bytes for current rule
		rule_raw = file_rules.read(rule_size)

		# Parse values
		name = rule_raw[0:20]
		rule_raw = rule_raw[20:]
		direction= struct.unpack('I',rule_raw[:4])[0]
		src_ip,_,src_k = struct.unpack('!IIB',rule_raw[4:13])
		# Skipping allignment padding of 3 bytes
		dst_ip,_,dst_k = struct.unpack('!IIB',rule_raw[16:25])
		# Skipping allignment padding of 1 byte
		src_port,dst_port = struct.unpack('!HH',rule_raw[26:30])
		protocol = struct.unpack('B',rule_raw[30:31])[0]
		# Skipping allignment padding of 1 byte
		ack,action = struct.unpack('II',rule_raw[32:40])
		
		# Convert values to readable descriptions
		direction = dir_strs.get(direction,'unknown')
		if(src_ip == 0):
			src_ip_str = 'any'
		else:
			src_ip_str = '{0}/{1}'.format(int2ip(src_ip),src_k)
		if(dst_ip == 0):
			dst_ip_str = 'any'
		else:
			dst_ip_str = '{0}/{1}'.format(int2ip(dst_ip),dst_k)
		proto_str = proto_strs.get(protocol,'unkown')
		src_port = port_strs.get(src_port,src_port)
		dst_port = port_strs.get(dst_port,dst_port)
		ack = ack_strs.get(ack,'unknown')
		action = action_strs.get(action,'unkown')

		print('{0} {1} {2} {3} {4} {5} {6} {7} {8}'.format(name,direction,src_ip_str,dst_ip_str,proto_str,src_port,dst_port,ack,action))
	file_rules.close()

def show_log():
	file_logs = open('/dev/{0}'.format(logs_char_device_name),'r')
	
	# Print header
	print('timestamp\t\t\tsrc_ip\t\t\tdst_ip\t\t\tsrc_port\tdst_port\tprotocol\thooknum\t\taction\treason\t\t\t\tcount')

	# Keep reading from log device until no more output is available
	log_raw = file_logs.read(log_size)
	i = 0
	while(log_raw != ''):
		# Unpack values from the current rule
		ts = struct.unpack('I',log_raw[:4])[0]
		proto, action, _, _, src_ip, dst_ip, src_port, dst_port= struct.unpack('!BBBBIIHH',log_raw[4:20])
		reason, count = struct.unpack('iI',log_raw[20:])
		src_ip = int2ip(src_ip)
		dst_ip =  int2ip(dst_ip)
		if(len(dst_ip) == 7):
			# Especially short IPs need an extra TAB
			dst_ip = dst_ip + '\t'
		proto = proto_strs.get(proto,'other')
		action = action_strs.get(action,action)
		ts = dt.datetime.fromtimestamp(ts).strftime('%d/%m/%Y %H:%M:%S')
		# if the reason is the rule number we need more TABs
		reason = reason_strs.get(reason, str(reason) + '\t\t')
		hooknum = NF_IP_FORWARD # For now, all rules apply only for the FORWARD hook
		# print the log row
		print('{0}\t\t{1}\t\t{2}\t\t{3}\t\t{4}\t\t{5}\t\t{6}\t\t{7}\t{8}\t\t{9}'.format(ts, src_ip, dst_ip, src_port, dst_port, proto, hooknum, action, reason, count))

		# Advance to next log row
		i += 1
		# Get all bytes for the next rule
		log_raw = file_logs.read(log_size)
	file_logs.close()

def clear_log():
	file_logs = open('/sys/class/{0}/{1}/{2}'.format(class_name,logs_device_name,reset_attr_name),'w')
	file_logs.write('0')
	file_logs.close()
	

def main(argv):
	usage_msg ='USAGE python {0} command [rules_path]\n'.format(argv[0])
	usage_msg += '\tcommand - One of the supported command: show_rules, load_rules, show_log, clear_log\n'
	usage_msg += '\trules_path - (Only for \'load_rules\' command) specifies the path to load the rules from'
	if(len(argv) < 2 or (len(argv) != 3 and argv[1] == 'load_rules')):
		print(usage_msg)
		return (-1)
	command = argv[1]
	if(command  == 'load_rules'):
		rules_path = argv[2]
		if not (path.exists(rules_path) and path.isfile(rules_path)):
			raise Exception('File not found at \'{0}\''.format(rules_path))
		load_rules(rules_path)
	elif(command == 'show_rules'):
		show_rules()
		pass
	elif(command == 'show_log'):
		show_log()
		pass
	elif(command == 'clear_log'):
		clear_log()
	else:
		# Invalid command name
		print(usage_msg)
		return (-1)
	return 0
if __name__ == '__main__':
	import sys
	sys.exit(main(sys.argv))
