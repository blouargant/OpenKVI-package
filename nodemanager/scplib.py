#!/usr/bin/python -u

import os
import socket
import paramiko

class Client:
	def __init__(self, host, user, password):
		self.host = host
		self.user = user
		self.password = password
		self.scp = None
		self.transport = None
		self.sock = None


	def connect(self):
		# Socket connection to remote host
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect((self.host, 22))

		# Build a SSH transport
		self.transport = paramiko.Transport(self.sock)
		self.transport.start_client()
		self.transport.auth_password(self.user, self.password)

		# Start a scp channel
		self.scp = self.transport.open_session()
  
  	def send(self, local, remote):
		f = file(local, 'rb')
	  	self.scp.exec_command('scp -v -t %s\n' % '/'.join(remote.split('/')[:-1]))
	  	self.scp.send('C%s %d %s\n' %(oct(os.stat(local).st_mode)[-4:],
						os.stat(local)[6],
						remote.split('/')[-1]))
		self.scp.sendall(f.read())

		# Cleanup
		f.close()

	def close(self):
		self.scp.close()
		self.transport.close()
		self.sock.close()
