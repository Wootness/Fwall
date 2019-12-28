import socket
import struct
import time
import threading
import select

class_name = 'fw'
manip_device_name = 'manipulations'
manip_attr_name = 'manipulations'

manip_inst_size = 14
ftp_manipulation_port = 210
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
		while(1):
			# check both sockets for info, whichever is available is processed
			print('selecting')
			ready = select.select([self.client,self.server], [], [], 100)
			print('selected')
			if self.client in ready[0]:
				# Check if client is ready
				print('Client is Ready ->> Reading!')
				temp  = self.client.recv(256)
				if (temp == b''):
					print('Client disconnected!')
					break
				client_buf += temp
				if not '\x0d\x0a' in client_buf:
					continue
				# Else, we have a complete command
				# Extract command
				command_len = client_buf.index('\x0d\x0a')+2
				command = client_buf[:command_len]

				# Remove command from buffer
				client_buf = client_buf[command_len:]

				# Check for required inteception - the PORT command
				if 'PORT' in command:
					# Parse ASCII parameters
					args = command[len('PORT '):].split(',')
					client_ip = (int(args[0]) << 24) | (int(args[1]) << 16) | (int(args[2]) << 8) | int(args[3])
					client_port = (int(args[4]) << 8) | int(args[5])
					server_ip = ip2int(self.server_info['ip'])
					# Notify kernel about the new expected TCP Connection
					send_kernel_manipulation_command(MANIPULATION_CMD_FTP_DATA, NO_MANIPULATION_PORT, 
													client_ip,client_port,server_ip,0)

				# any non-interesting command (and also PORT commands continue here)
				print('Client -> Server: \033[91m{0}\033[00m'.format(temp.rstrip()))
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
		run_server(('',ftp_manipulation_port))
	except Exception as error:
		print('ERROR: {0}'.format(error))
		return 1

if __name__ == '__main__':
	import sys
	sys.exit(main(sys.argv))