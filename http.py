import socket
import struct
import time
import threading
import select

class_name = 'fw'
manip_device_name = 'manipulations'
manip_attr_name = 'manipulations'

manip_inst_size = 14
http_manipulation_port = 800
NO_MANIPULATION_PORT = 0
MANIPULATION_CMD_INST = 0

HTTP_HEADERS_END = '\r\n\r\n'
HTTP_CONTENT_TYPE_HEADER = 'Content-Type:'
HTTP_HEADERS_SEPERATOR = '\r\n'
CONTENT_TYPE_ZIP = 'application/zip'
CONTENT_TYPE_CSV = 'text/csv'


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
		# Start by reading request (maybe in parts) from the client
		req_sent = False
		while not HTTP_HEADERS_END in client_buf:
			temp = self.client.recv(256)
			if (temp == b''):
				print('client disconnected!')
				break
			client_buf += temp
		else:
			# found HTTP request end
			req_len = client_buf.index(HTTP_HEADERS_END) + len(HTTP_HEADERS_END)
			request = client_buf[:req_len]
			print('Client\'s request found: \033[91m{0}\033[00m'.format(request.rstrip()))
			self.server.send(request)
			req_sent = True
		
		if not req_sent:
			# ser prematurly disconnected, dropping connection	  
			self.client.close()
			self.server.close()
			return
		
		# Request sent, try read response from server
		server_buf = b''
		while not HTTP_HEADERS_END in server_buf:
			temp = self.server.recv(256)
			if (temp == b''):
				print('server disconnected!')
				break
			server_buf += temp
		else:
			# found end of HTTP headers of response
			# Searching for content type header
			res_len = server_buf.index(HTTP_HEADERS_END) + len(HTTP_HEADERS_END)
			resp = server_buf[:res_len]
			print('Server\'s response found: \033[96m{0}\033[00m'.format(resp.rstrip()))
			contnt_type_start = server_buf.lower().index(HTTP_CONTENT_TYPE_HEADER.lower()) + len(HTTP_CONTENT_TYPE_HEADER)
			temp = server_buf[contnt_type_start:]
			contnt_type_end = temp.index(HTTP_HEADERS_SEPERATOR)
			con_type = temp[:contnt_type_end].strip()

			# Check for forbidden types
			if (con_type == CONTENT_TYPE_ZIP or con_type == CONTENT_TYPE_CSV):
				print('Server\'s response contained forbidden type, dropping connection.')
				# Forbidden content type found, dropping connections
				self.client.close()
				self.server.close()
				return

			# else - content approved. Sending header than sending any data left
			self.client.send(server_buf)
			while 1:
				temp = self.server.recv(256)
				if (temp == b''):
					print('server disconnected!')
					break
				self.client.send(temp)
		print('Closing client')
		self.client.close()
		print('Closed client')
		print('Closing server')
		self.server.close()
		print('Closed server')

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
		run_server(('',http_manipulation_port))
	except Exception as error:
		print('ERROR: {0}'.format(error))
		return 1

if __name__ == '__main__':
	import sys
	sys.exit(main(sys.argv))