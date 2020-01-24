import socket
import struct
import time
import threading
import select
import re

class_name = 'fw'
manip_device_name = 'manipulations'
manip_attr_name = 'manipulations'

manip_inst_size = 14
smtp_manipulation_port = 250
NO_MANIPULATION_PORT = 0
MANIPULATION_CMD_INST = 0
MANIPULATION_CMD_FTP_DATA =1

# Helper method to turn an integer into an IPv4 address strings and vice versa
# Taken from: https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python
def ip2int(addr):
	return struct.unpack("!I", socket.inet_aton(addr))[0]
def int2ip(addr):
	return socket.inet_ntoa(struct.pack("!I", addr))

# Read from the kernel's device which indicated the next
# awaiting connections info (IPs, Ports)
def get_awaiting_connection():
	manip_dev = open('/sys/class/{0}/{1}/{2}'.format(class_name,manip_device_name,manip_attr_name),'r')

	inst_raw = manip_dev.read(manip_inst_size)
	client_ip,server_ip,client_port,server_port,_ = struct.unpack('!IIHHH',inst_raw)
	client_ip = int2ip(client_ip)
	server_ip = int2ip(server_ip)

	manip_dev.close()

	return {'client':{'ip':client_ip,'port':client_port},'server':{'ip':server_ip,'port':server_port}}

# Inform the kernel module of the 5-tuple of a manipulated connection
def send_kernel_manipulation_command(cmd_type,manip_port,client_ip,client_port,server_ip,server_port):
	# Creating magic number header
	buf = b'\x56\x78'
	# Appending IPs, Ports
	buf += struct.pack('!BIIHHH',cmd_type,client_ip,server_ip,client_port,server_port,manip_port)
	
	manip_dev = open('/sys/class/{0}/{1}/{2}'.format(class_name,manip_device_name,manip_attr_name),'w')
	manip_dev.write(buf)
	manip_dev.close()

start_of_line_regex_fmt = "^\s{0,50}"
regex_or = ")|(?:"
final_regex_string = 	(start_of_line_regex_fmt +
			"(?:(?:" +
			r"[a-zA-Z_][\w]{0,50}\s{0,50}[-+*&|^\\]?=" +								# Variable assignments
			regex_or +
			r"[a-zA-Z_][\w]{0,50}(?:->|\.)[a-zA-Z_][\w]{0,50}\s{0,10}[-+*&|^\\]?=" +	# Fields assignments (accessed with -> or dot)
			regex_or +
			r"[a-zA-Z_][\w]{0,50}\[[\w]{0,50}\]\s{0,10}[-+*&|^\\]?=" +					# Array assignments (accessed with [])
			regex_or +
			r"[a-zA-Z_][\w]{0,50}\s?\(" +												# Function calls
			regex_or +
			r"(?:static\s{1,10})?(?:const\s{1,10})?(?:(?:struct|enum)\s{1,10})?[a-zA-Z_][\w]{0,50}" +
			r"(?:\s{1,10}\*{0,3}|\s{0,10}\*{0,3}\s|\s)\s{0,10}(?:const\s{0,10})?[a-zA-Z_][\w]{0,50}\s{0,10}[;=]" +		# Var declerations
			regex_or +
			r"(?:static\s)?[a-zA-Z_][\w]{0,50}\s{1,10}[a-zA-Z_][\w]{0,50}\((?:\)|\s{0,10}[a-zA-Z0-9])" +				# Function declerations
			regex_or +
			r"[\{\}]\s{0,10}$" +														# Lines with a single (open or close) bracket
			regex_or +
			r"(?:/\*|\*/)" +															# Long comments starts and ends
			regex_or +
			r"(?:break|continue|(?:return\s{0,10}[\w]{0,50}))\s?[;(\[]" +				# Control flow key words
			regex_or +
			r"(?:if|while|for|switch)\s?\(" +											# Scope starters - if, while, for, switch
			regex_or +
			r"case\s[\w]{0,50}:" +														# Case line
			regex_or +
			r"do\s{0,10}{\s{0,10}$" +													# do loop keyword
			regex_or +
			r"typedef\s{1,3}(?:struct\s{1,3})?[a-zA-Z_][\w]{0,50}" +					# Typedef
			regex_or +
			r"enum\s{0,3}[a-zA-Z_][\w]{0,50}" +											# Enum definitions
			"))")
forbidden_pattern = re.compile(final_regex_string, flags = re.MULTILINE)

# Checks for data leakage (C Code)
# Returns: 'True' if data is forbidden, 'False' otherwise
def run_dlp_analysis(data):
	count = 0
	for match in forbidden_pattern.finditer(data):
		count += 1
		if count > 5:
			break
	return count >= 5

class Single_user_handler(threading.Thread):
	def __init__(self,client,manipulation_inst):
		super(Single_user_handler,self).__init__()
		self.client = client
		self.inst = manipulation_inst
		# Prepare socket for the server connection
		self.server = socket.socket()
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
		# Binding socket before connection to server.
		# We do this to get the expected SOURCE PORT because the first (SYN) packet
		# we inform the kernel so it doesn't drop our connection
		self.server.bind(('0.0.0.0',0))
		manip_port = self.server.getsockname()[1]
		
		# Write instructions to kernel	
		self.client_info = manipulation_inst['client']
		self.server_info = manipulation_inst['server']
		client_ip = self.client_info['ip']
		client_port = self.client_info['port']
		server_ip = self.server_info['ip']
		server_port = self.server_info['port']
		client_ip = ip2int(client_ip)
		server_ip = ip2int(server_ip)
		send_kernel_manipulation_command(MANIPULATION_CMD_INST,manip_port,
										client_ip,client_port,
										server_ip,server_port)

		# Actually connect to the server, might throw exceptions if refused/timedout
		self.server.connect((self.server_info['ip'],server_port))
	
	def run(self):
		client_buf = b''
		client_mail_body_buf = b''
		# using a flag to tell if we are collecting client's data part
		reading_mail_body = False
		while(1):
			# check both sockets for info, whichever is available is processed
			ready = select.select([self.client,self.server], [], [], 100)
			if self.client in ready[0]:
				# Check if client is ready
				print('Client is Ready ->> Reading!')
				temp  = self.client.recv(256)
				if (temp == b''):
					print('Client disconnected!')
					break
					
				if reading_mail_body :
					# Aggregating user mail content
					client_mail_body_buf += temp

					# Check for indication that the data part is ending
					if '\x0d\x0a.\x0d\x0a' in client_mail_body_buf:
						msg_len = client_mail_body_buf.index('\x0d\x0a.\x0d\x0a')+5
						msg = client_mail_body_buf[:msg_len]
						# Anything left in the buffer goes to the normal client buffer
						temp = client_mail_body_buf[msg_len:]

						# Check mail content
						forbidden = run_dlp_analysis(msg)
						print('Client\'s mail content: \033[91m{0}\033[00m'.format(msg.rstrip()))
						if(forbidden):
							print('Client\'s mail contained a forbidden mail content, dropping connection.')
							self.client.close()
							self.server.close()
							return
						print('Client\'s mail content is OK.')
						self.server.send(msg)
						client_mail_body_buf = ''

						# Resetting data aggregation flag
						reading_mail_body = False

				# Not using an else case so I can 'fall' into that case right after finishing user data part
				if not reading_mail_body:
					client_buf += temp
					if not '\x0d\x0a' in client_buf:
						continue
					# Else, we have a complete command
					# Extract command
					command_len = client_buf.index('\x0d\x0a')+2
					command = client_buf[:command_len]

					# Remove command from buffer
					client_buf = client_buf[command_len:]

					# Check if the client is starting it's data part
					if 'data\x0d\x0a' in command.lower():
						reading_mail_body = True
						print('reading_mail_body is NOW TRUEEEE : {0}'.format(reading_mail_body))
						# Mark for next iteration

					# any non-interesting command (and also PORT commands continue here)
					print('Client -> Server: \033[91m{0}\033[00m'.format(temp.replace('\x0d','\\r').replace('\x0a','\\n')))
					self.server.send(command)
			elif self.server in ready[0]:
				# Server is ready
				# just forward anything we can read back to the client
				temp = self.server.recv(256)
				if (temp == b''):
					print('Server disconnected!')
					break
				print('Server -> Client: \033[96m{0}\033[00m'.format(temp.rstrip()))
				self.client.send(temp)
		self.client.close()
		self.server.close()

def run_server(address):
	listener = socket.socket()
	listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
	listener.bind(address)
	listener.listen(100)
	print('Listening (Address: {0})...'.format(address))
	while(1):
		try:
			client, c_address = listener.accept()
			print('New client found! Endpoint: {0} '.format(c_address))
			inst = get_awaiting_connection()
			while inst['client']['ip'] != c_address[0] or inst['client']['port'] != c_address[1] :
				inst = get_awaiting_connection()
		except Exception as e:
			print('ERROR IN ACCEPT: {0}'.format(e))
			raise
		try:
			# Possible errors are connection refuse from server or timeout
			handler = Single_user_handler(client,inst)
		except Exception as e:
			print(e)
			client.close()
			continue
		handler.start()

def main(argv):
	try:
		run_server(('',smtp_manipulation_port))
	except Exception as error:
		print('ERROR: {0}'.format(error))
		return 1

if __name__ == '__main__':
	import sys
	sys.exit(main(sys.argv))