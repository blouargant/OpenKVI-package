#!/usr/bin/python -u
"""
Library for general functions
"""

import os
import sys
import SocketServer
import time
import datetime
import threading
import json
import collections
import time
import fcntl
from rwlock import RWLock
import subprocess
#import zmq

class MSGControler:
	#def __init__(self, listen_ip, listen_port, log_file, debug):
	def __init__(self, configDic):
		"""
		Init Controler class
		"""
		self.running = True
		self.config = configDic
		self.log_file = self.config["log"]
		self.debug = self.config["debug"]
		self.security = self.config["security"]
		self.clients = {}
		self.lock = RWLock()
		## Start TCP comm server ##
		listen_ip = self.config["listen_ip"]
		listen_port = self.config["listen_port"]
		try:
			self.server = tcpServer((listen_ip,listen_port), handleConnection, self.clients, self.debug, self.security )
		except:
			self.log_error("Unable to bind TCP socket %s:%s !" % (listen_ip,listen_port))
			proc = subprocess.Popen(["ss", "-pant"], stdout=subprocess.PIPE)
			code = proc.wait()
			for aline in proc.stdout:
				if (str(listen_ip)+':'+str(listen_port)) in aline and "LISTEN" in aline:
					tmpstr1 = re.sub(').*', '', re.sub('.*(', '', aline))
					pid = re.sub(',.*', '', re.sub('.*pid=', tmpstr1))
					prog = re.sub('.*"', '', re.sub('",.*', '', aline))
					self.log_warning("Process %s, PID %s, is binding port %s. It will be killed." % (prog, pid, listen_port))
					os.system("kill -9 %s" % pid)
		
			time.sleep(10)
			self.log_info("Trying again to bind %s on %s." % (listen_port, listen_ip))
			self.server = tcpServer((listen_ip,listen_port), handleConnection, self.clients, self.debug, self.security )

		self.comm_thread = threading.Thread(target=self.server.serve_forever)
		self.comm_thread.daemon = True
		self.comm_thread.start()
		##### Send a keepalive message every minutes (60 sec) ##
		self.keepalive = KeepAliveTimer(60, self.send_keepalive, ["KeepAliveTimer"])
		self.keepalive.start()
	
	def log_error(self, newline):
		self.log(newline, "ERROR")
	
	def log_warning(self, newline):
		self.log(newline, "WARNING")
	
	def log_info(self, newline):
		self.log(newline, "INFO")
	
	def log_event(self, newline):
		self.log(newline, "EVENT")
	
	def log_debug(self, newline):
		if self.debug == True :
			self.log(newline, "DEBUG")

	def log(self, newline, level="INFO"):
		LOG_SIZE = os.path.getsize(self.log_file)
		# if > 1M create a new file
		if LOG_SIZE > 1000000:
			if os.path.exists(self.log_file+".4"):
				os.remove(self.log_file+".4")
				os.rename(self.log_file+".3", self.log_file+".4")
			if os.path.exists(self.log_file+".3"):
				os.rename(self.log_file+".3", self.log_file+".4")
			if os.path.exists(self.log_file+".2"):
				os.rename(self.log_file+".2", self.log_file+".3")
			if os.path.exists(self.log_file+".1"):
				os.rename(self.log_file+".1", self.log_file+".2")
				
			os.rename(self.log_file, self.log_file+".1")
			if os.path.exists('/opt/virtualisation/openkvi/debug'):
				os.remove('/opt/virtualisation/openkvi/debug')
			logs = open(self.log_file,'w')

		else:
			logs = open(self.log_file,'a')

	 	timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
		logs.write(timestamp+"::["+level+"]::"+newline+"\n")
		logs.close()
	
	def print_debug(self, msg):
		if self.debug == True :
			self.log_debug(msg)
			print msg

	def tell_all(self, event, data):
		self.keepalive.stop()
		self.print_debug("telling all %s %s"% (event, data))
		line = event+";"+json.dumps(data)
		## Acquire lock so that no messages are sent 
		## simultanously 
		self.lock.acquire_write()
		res = self.server.writeToAll(line)
		## Wait 500 ms between two message to prevent 
 		## clients being overwhelmed 
		time.sleep(0.5)
		self.lock.release()
		self.keepalive.start()
	
	def stop(self):
		self.print_debug("stop tcp server")
		self.keepalive.stop()
		self.server.socket.close()
	
	def send_keepalive(self):
		res = self.server.writeToAll("keep alive")




class tcpServer(SocketServer.ThreadingTCPServer):
	def __init__(self, server_address, RequestHandlerClass, clients, debug, security):
		self.allow_reuse_address = True
		SocketServer.ThreadingTCPServer.__init__(self,server_address,RequestHandlerClass)
		self.clients = clients
		#self.arg2 = arg2
		self.rwlock = RWLock()
		self.debug = debug
		self.security = security
	
	def print_debug(self, msg):
		if self.debug == True :
			print msg

	def writeToAll(self, line):				
		lines = []
		lines.append(line)
		msg = {}
		msg['messages'] = lines
		try:
			self.rwlock.acquire_read()
			keys = self.clients.keys()
			self.rwlock.release()
		except:
			err = str(sys.exc_info()[1]).strip("'")
			return 0

		for an_id in keys:
			self.clients[an_id]['lock'].acquire_write()
			conn = self.clients[an_id]['connection']
			try :
				#self.print_debug("trying to say %s to %s" % (line.strip(), an_id))
				conn.wfile.write(json.dumps(msg)+"\n")
				self.clients[an_id]['lock'].release()

			except:
				self.print_debug("Not able to speak to %s" %  an_id)
				self.clients[an_id]['lock'].release()
				timestamp = self.clients[an_id]["timestamp"]
				if timestamp != 0:
					timeout = datetime.datetime.now() - timestamp
					if timeout > datetime.timedelta(seconds = 20):
						self.print_debug("connection to %s timed out !" % an_id)
						try:
							conn.finish()
						except:
							self.print_debug("connection to %s is already finished" % an_id)
						del self.clients[an_id]
						if self.security != "low":
							#curl -k https://localhost/_auth/unset/?id=12345"
							url = 'https://localhost/_auth/unset/?id='+an_id
							proc = subprocess.Popen(['curl','-k',url], stdout=subprocess.PIPE)
							code = proc.wait()
				else:
					self.clients[an_id]['lock'].acquire_write()
					self.clients[an_id]['timestamp'] = datetime.datetime.now() 
					self.clients[an_id]['messages'].append(line)			
					self.clients[an_id]['lock'].release()
	

		return 0


class handleConnection(SocketServer.StreamRequestHandler):

	def handle(self):
		while True:
			try:
				#self.client_id = self.rfile.readline().strip()
				data = self.rfile.readline().strip()
				if data.find("::") > 0:
					infos = data.split('::')
					self.client_id = infos[0]
					remote_ip = infos[1]
				else:
					self.client_id = ""

				if self.client_id:
					try :
						if self.server.clients.has_key(self.client_id):
							self.server.clients[self.client_id]['lock'].acquire_write()
							self.server.clients[self.client_id]['connection'] = self
							if len(self.server.clients[self.client_id]['messages']) > 0:
								msg = {}
								msg['messages'] = self.server.clients[self.client_id]['messages']
								reply = json.dumps(msg)
								self.wfile.write(reply+"\n")
								self.server.clients[self.client_id]['timestamp'] = 0
								self.server.clients[self.client_id]['messages'] = []
								self.server.clients[self.client_id]['lock'].release()
								return 0
							self.server.clients[self.client_id]['lock'].release()
					
						else:
							newClient = {}
							newLock = RWLock()
							newClient['connection'] = self
							newClient['messages'] = []
							newClient['timestamp'] = 0
							newClient['lock'] = newLock
							self.server.rwlock.acquire_write()
							self.server.clients[self.client_id] = newClient
							self.wfile.write("hello\n")
							self.server.rwlock.release()
							print "Messenger: self.server.security"
							if self.server.security != "low":
								print "Adding ID "+self.client_id+"to nginx"
								#curl -k https://localhost/_auth/set/?auth="ID:12345, IP:10.165.68.67"
								url = 'https://localhost/_auth/set/?auth="ID:'+self.client_id+', IP:'+remote_ip+'"'
								proc = subprocess.Popen(['curl','-k',url], stdout=subprocess.PIPE)
								code = proc.wait()
							
							self.server.print_debug("Received connection ID:"+self.client_id+" for client IP:"+remote_ip) 
							return 0
			
			
					except:
						self.server.print_debug("Error: %s , request from %s" % (str(sys.exc_info()[1]), self.client_id))
				else:
					break
			except:
				self.server.print_debug("Error: %s , reading from %s" % (str(sys.exc_info()[1]), self.client_id))

class KeepAliveTimer:
	def __init__(self, tempo, target, args= [], kwargs={}):
		self._target = target
		self._args = args
		self._kwargs = kwargs
		self._tempo = tempo

	def _run(self):
		self._timer = threading.Timer(self._tempo, self._run)
		self._timer.start()
		#self._target(*self._args, **self._kwargs)
		self._target()
		
	def start(self):
		self._timer = threading.Timer(self._tempo, self._run)
		self._timer.start()

	def stop(self):
		self._timer.cancel()


#class zmqPublisher(threading.Thread):
#	"""ZeroMQ provider"""
#	def __init__(self, ip, port):
#		threading.Thread.__init__ (self)
#		self.ip = ip
#		self.port = port		
#
#	def run(self):
#		self.context = zmq.Context()
#		self.socket = self.context.socket(zmq.PUB)
#		self.socket.bind("tcp://"+self.ip+":"+self.port)
#
#	def sendmsg(self, message):
#		self.socket.send_string(message)
#		#self.socket.send(message)
#
#	def stop(self):
#		message = "ALL END CONNECTION"
#		self.socket.send(message)
#		self.socket.close()
#		self.context.term()	
			
