#!/usr/bin/python -u
""" 
Handle functions specifique to virtualization nodes 
"""

import os
import time
import datetime
import libvirt
import threading
import sys
import scplib
import paramiko
import socket
import math
import platform
from xml.dom.minidom import parseString
import xmltodict
from rwlock import RWLock
from networklib import NetworkControler
from storageslib import StorageControler
import json
import subprocess
import re
from switchlib import switch
import ssh
import rsync
import pwd, grp
import bash

class NodesControler:
	def __init__(self, logger, eventListener, vm_handle, database):
		""" Contain node commands """
		self.logger = logger
		self.nlock = RWLock()
		self.nlist = {}
		self.eventListener = eventListener
		self.vm_handle = vm_handle
		self.db = database
		self.shellinabox_ports = []
	
	def send_event(self, node, status, detail):
		message = {}
		message['event'] = "NODE_STATUS"
		message['node'] = node
		message['sender'] = "Node Manager"
		message['status'] = status
		message['detail'] = detail
		self.logger.tell_all("EVENT", message)
		
	def load(self):
		nodelist = self.db.list_nodes()
		if nodelist['status'] == "failed":
			self.db.close()
			return -1
		
		else:
			vmlist = self.db.list_vms()
			for node in nodelist['nodes']:
				res = self.connect( node['name'], node['hypervisor'], "ssh", node['ip'])
				if res['state'] == "connected":
					for vm in vmlist['vms']:
						if vm['server'] == node['name']:
							self.logger.log_info("Initialising domain "+vm['name'])
							try:
								conn = self.nlist[node['name']]['connection']
								domain = conn.lookupByName(vm['name'])
								self.vm_handle.init_vm(vm['name'], node['name'], domain)
							except:
								self.logger.log_error("Failed to initialise Domain %s: %s" % (vm['name'], sys.exc_info()[1]))
		
		return 0
	
	def add_etchosts(self, node, ip):
		""" Add name and ip of node to /etc/hosts """
		hosts_file = open("/etc/hosts", "r")
		lines = hosts_file.readlines()
		hosts_file.close()
		toadd = True
		towrite = False
		for aline in lines:
			if node in aline and ip not in aline:
				# The Node has already been configured with another IP
				return False
			
		for aline in lines:
			if ip in aline and aline[0] != "#":
				if node in aline:
					toadd = False
				else :
					i = lines.index(aline)
					lines.pop(i)
					newline = aline.strip()+" "+node+"\n"
					lines.insert(i, newline)
					toadd = False
					towrite = True
		if toadd :
			lines.append(ip+"    "+node+"\n")
			towrite = True
		if towrite:
			hosts_file = open("/etc/hosts", "w")
			hosts_file.writelines(lines)
			hosts_file.close()
		
		return True
		
	def remove_etchosts(self, node, ip):
		""" Add name and ip of node to /etc/hosts """
		hosts_file = open("/etc/hosts", "r")
		lines = hosts_file.readlines()
		hosts_file.close()
		toremove = ""
		towrite = False
		for aline in lines:
			if ip in aline and aline[0] != "#":
				if node in aline:
					tmpstr1 = aline.replace(node, "")
					tmpstr2 = tmpstr1.replace(ip, "")
					tmpstr3 = tmpstr2.strip()
					if tmpstr3 == "":
						toremove = aline
					else :
						i = lines.index(aline)
						lines.pop(i)
						lines.insert(i, tmpstr1)
						towrite = True
		if toremove != "" :
			lines.remove(toremove)
			towrite = True
		if towrite:
			hosts_file = open("/etc/hosts", "w")
			hosts_file.writelines(lines)
			hosts_file.close()
		
		return True
	
	def read_etchosts(self):
		""" Get /etc/hosts """
		hosts_file = open("/etc/hosts", "r")
		lines = hosts_file.readlines()
		hosts_file.close()
		content = []
		for aline in lines:
			aline = aline.replace("\t", "    ")
			entry = {}
			aline.strip()
			args = aline.split(' ')
			entry['ip'] = args[0] 
			names = ""
			for a_name in args[1:] :
				if a_name != "":
					if names == "":
						names = a_name.strip()
					else:
						names = names+", "+a_name.strip()
			entry['names'] = names
			content.append(entry)
		return content
	
	def write_etchosts(self, data):
		""" write content to /etc/hosts """
		content = json.loads(data)
		lines = []
		for entry in content:
			ip = entry['ip']
			names = ''
			tmp_names = entry['names'].replace(',', ' ')
			tmp_names_list = tmp_names.split(' ')
			for a_name in tmp_names_list:
				if a_name != "":
					if names == "":
						names = a_name.strip()
					else:
						names = names+" "+a_name.strip()
		
			lines.append(ip+"    "+names+"\n")
		
		hosts_file = open("/etc/hosts", "w")
		hosts_file.writelines(lines)
		hosts_file.close()
		## We can add here code to populate /etc/hosts on every managed nodes ##
		## ##
		return "done"

	############# NODES FUNCTIONS ################################
	def get(self, node, request, options):
		""" Get general libvirt information from a node """
		result = "Unknown command"
		force = "false"
		path = "/root/WaveMaker/projects/openkvi/webapproot/resources/jarmon/monitor/data"
		self.logger.log_debug("trying to get %s for %s" % (request, node))
		for option in options:
			if "force" in option:
				args = option.split('=')
				force = args[1].strip()
			if "path" in option:
				args = option.split('=')
				path = args[1].strip()
		if request == "vm_list":
			result = self.get_vm_list(node)
		if request == "capabilities":
			result = self.get_capabilities(node, options)
		if request == "info":
			result = self.get_info(node, options)
		if request == "ressources":
			result = self.get_node_usage(node, options)
		if request == "networks":
			result = self.get_node_networks(node, force)
		if request == "time":
			result = self.get_node_time(node, options)
		if request == "snmp":
			result = self.get_node_snmp(node, options)
		if request == "hel":
			result = self.get_node_hardware_events(node)
		if request == "performances":
			result = self.get_node_collectd_data(node, path)
		if request == "logs":
			result = self.get_node_logs(node)
		if request == "all_nodes_info":
			result = self.get_all_nodes_infos()
		if request == "virt-top":
			result = self.get_virt_top(node)
		if request == "inspect_vm":
			result = self.inspect(node, options)
		if request == "probe_nodes":
			result = self.probe_nodes()
		return result
	
	def list_directory(self, node, path):
		result = []
		try:
			cmd = 'ls -Llh --full-time '+path
			cmd += ' | sed -e "s/^total .*$//"'
			cmd += ' | sed -e "s/ /::/g"'
			cmd += ' | sed -e "s/:*:/::/g"'
			cmd += ' | sed -e "s/::->::/ -> /g"'
			res, error = ssh.run(node, cmd)
			if error:
				result = error
			else:
				result = res
			
		except:
			result.append(str(sys.exc_info()[1]))
			self.logger.log_error("Failed to list %s remote directory: %s" % (node, result))
		return result
	
	def get_file_info(self, node, path):
		result = []
		try:
			cmd = 'file -bkr '+path
			res, error = ssh.run(node, cmd)
			if error:
				result.append(error)
			else:
				result.append('\n'.join(res))
			
			cmd = 'qemu-img info '+path
			res, error = ssh.run(node, cmd)
			if error:
				result.append(error)
			else:
				result.append('\n'.join(res))
			
		except:
			result.append(str(sys.exc_info()[1]))
			self.logger.log_error("Failed to get %s inforation: %s" % (path, result))
		return result
	
	def get_virt_top(self, node):
		result = []
		try:
			cmd = 'virt-top --stream -n 2 | grep -v virt-top | grep -v "%MEM" | sed -e "s/ /;/g" | sed -e "s/;;*/;/g"'
			res, error = ssh.run(node, cmd)
			if error:
				result.append(error)
			else:
				result = res
			
		except:
			result.append(str(sys.exc_info()[1]))
			self.logger.log_error("Failed to get virt-top for %s: %s" % (node, result))
		return result
	
	def inspect_vm(self, node, options):
		result = {}
		try:
			for option in options: 
				if "vm" in option:
					args = option.split('=')
					vm = args[1].strip()
			cmd = 'virt-inspector2 -d '+vm
			res, error = ssh.run(node, cmd)
			if error:
				result = error
			else:
				result = xmltodict.parse(res)
			
		except:
			result = str(sys.exc_info()[1])
			self.logger.log_error("Failed to get virt-top for %s: %s" % (node, result))
		return result
	
	def probe_nodes(self):
		result = []
		try:
			cmd = 'onectl neighbors.names --browse all'
			res, error = bash.run(cmd)
			if error:
				result.append(error)
			else:
				#{"name":"fr-cae-kvm36 Virtual Machine Manager local","hostname":"fr-cae-kvm36.local","address":"10.165.110.36","port":"65535","info":"kvm"}
				#fr-cae-kvm35 @ 10.165.110.35 (00:22:64:07:1f:88) - ['SSH', 'Virtualization', 'kvm']
				lines = res.split('\n')
				lines = filter(None, lines)
				for line in lines:
					dic = {}
					if re.search ("Virtualization" , line):
						dic["name"] = re.sub(" @.*", "", line)
						dic["ip"] = re.sub(" .*", "", re.sub(".*@ ", "", line))
						dic["info"] = ""
						if re.search("'kvm'", line):
							dic["info"] = "kvm"
						elif re.search("'qemu'", line):
							dic["info"] = "qemu"
						result.append(dic)
						
		except:
			result.append(str(sys.exc_info()[1]))
			self.logger.log_error("Failed to browse nodes: %s" % result)
		return result
	
	def exchange_keys(self, user, host, passwd, ip):
		""" 
		Exchange SSH keys between a virtualization node
		and the management interface
		"""
		homedir = os.path.expanduser("~"+user)
		# Check/Generate nodemanger DSA key
		if not os.path.exists(homedir+'/.ssh/id_dsa') :
			os.system('ssh-keygen -q -t dsa -N "" -f '+homedir+'/.ssh/id_dsa')
		
		# Connect to remote hosting node
		sshc = paramiko.SSHClient()
		sshc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		sshc.connect(hostname = host, username=user, password=passwd)
		hostname =  platform.node()
		scpc = scplib.Client(host, user, passwd)
		
		### SSH key exchange :
		# Remove previous key
		cmd = 'perl -p -i -e "s/.* '+user+'\@'+hostname+'\\n$//" '+homedir+'/.ssh/authorized_keys'
		stdin, stdout, stderr = sshc.exec_command(cmd)
		
		scpc.connect()
		# Copy nodemanager key to remote node
		os.system("cp -f "+homedir+"/.ssh/id_dsa.pub "+homedir+"/.ssh/id_dsa.pub."+hostname)
		scpc.send(homedir+"/.ssh/id_dsa.pub."+hostname, homedir+"/.ssh/id_dsa.pub."+hostname)
		scpc.close()
		# Insert key in authorized_keys
		cmd = "cat "+homedir+"/.ssh/id_dsa.pub."+hostname+" >> "+homedir+"/.ssh/authorized_keys"
		stdin, stdout, stderr = sshc.exec_command(cmd)
		# Remove temporary key from remote node
		cmd = "rm -f "+homedir+"/.ssh/id_dsa.pub."+hostname+" >> "+homedir+"/.ssh/authorized_keys"
		stdin, stdout, stderr = sshc.exec_command(cmd)
		
		# remove potential old keys in known_hosts
		low_host = host.lower() 
		cmd = 'perl -p -i -e "s/'+low_host+',.* ssh-rsa .*\\n$//" '+homedir+'/.ssh/known_hosts'
		os.system(cmd)
		cmd = 'perl -p -i -e "s/'+low_host+' ssh-rsa .*\\n$//" '+homedir+'/.ssh/known_hosts'
		os.system(cmd)
		cmd = 'perl -p -i -e "s/.*,'+ip+' ssh-rsa .*\\n$//" '+homedir+'/.ssh/known_hosts'
		os.system(cmd)
		cmd = 'perl -p -i -e "s/'+ip+' ssh-rsa .*\\n$//" '+homedir+'/.ssh/known_hosts'
		os.system(cmd)
		#Automaticaly add remote host to root's known_hosts:
		cmd = 'ssh -o StrictHostKeyChecking=no root@'+host+' "exit" 2>/tmp/test-ssh'
		os.system(cmd)
		test_file = open("/tmp/test-ssh", "r")
		lines = test_file.readlines()
		test_file.close()
		result = "Failed"
		for a_line in lines:
			if "Permanently added" in a_line:
				result = "Success"
		
		return result
	
	def connect(self, node, type, transport, ip):
		"""
		Internal: connect each node in database 
		"""
		user = "root"
		result = {}
		transport = "ssh"
		system = "/system"
		if type == "kvm":
			driver = "qemu"
		elif type == "esx":
			transport = ""
			system = ""
			driver = type
		else:
			driver = type
		uri = driver+"+"+transport+"://"+user+"@"+node+system
		
		conn_opened = "false"
		self.nlock.acquire_read()
		if self.nlist.has_key(node):
			conn_opened = self.nlist[node]["state"]
		self.nlock.release()
		result['state'] = conn_opened
		if conn_opened != "open":
			if transport == "ssh":
				self.logger.log_info("Initialising connection to "+type+" node "+node+" ...")
				# Test SSH connection before going any further
				# with a 30 seconds timeout
				res, error = ssh.run(node, 'ls /etc/', 15, '-o BatchMode=yes')
				if len(res) == 0:
					error = "Node is unreachable"
				
				if error:
					result['state'] = "Failed to establish a ssh connection: "+error
					self.logger.log_error("Failed to establish a ssh connection: "+error)
					if self.nlist.has_key(node):
						self.nlist[node]["state"] = result['state']
					else:
						newNode = {}
						newNode["type"] = type
						newNode["uri"] = uri
						newNode["ip"] = ip
						newNode["state"] = "Failed to establish a ssh connection"
						self.nlist[node] = newNode
					return result
			
			result = self.open_connection(node, uri, type)
		self.logger.log_debug(node+" connection procedure finished")
		
		return result
	
	def open_connection(self, node, uri, type):
		""" 
		Add a connection to a node 
		and start a libvirtlistener session
		"""
		if self.nlist.has_key(node):
			newNode = self.nlist[node]
		else:
			newNode = {}
			newNode["type"] = type
			newNode["uri"] = uri
			newNode["ip"] = '0.0.0.0'
			newNode["state"] = "unknown"
			newNode["webshell"] = {}
			newNode["system"] = {}
			newNode["connection"] = None
			newNode["counter"] = 0
		
		self.logger.log_debug("trying to connect to "+node)
		result = {}
		result['ip'] = '0.0.0.0'
		result['state'] = 'disconnected'
		result['webshell'] = '0'
		result['webshells'] = '0'
			
		
		try :
			self.logger.log_info("Opening libvirt connection "+uri)
			conn = libvirt.open(uri)
			conn.setKeepAlive(2, 5)
		except :
			result['state'] = "Failed to open libvirt connection to "+node
			self.logger.log_error("Failed to open libvirt connection to %s" % node)
			newNode["state"] = "Failed to open libvirt connection to "+node
			self.nlist[node] = newNode
			return result
			
		try:
			self.logger.log_info("libvirt connection to "+node+" opened")
			newNode["connection"] = conn
			newNode["counter"] = 0
			newNode["state"] = "open"
			self.nlock.acquire_write()
			self.eventListener.register(conn, node)
			self.nlock.release()
			ip = socket.gethostbyname(node)
			newNode["ip"] = ip
			result['ip'] = ip
			result['state'] = "connected"
			#initialise Network controler
			newNode["netcontroler"] = NetworkControler(node, conn, self.logger)
			newNode["pools"] = StorageControler(node, conn, self.logger)
			
			self.nlist[node] = newNode
			# Set KVM node's security level
			self.set_node_security(node, self.logger.security)
			# Get System Information
			self.get_system(node)
			
			# CHeck collectd for performance monitoring
			err = self.check_node_collectd(node)
			if err:
				self.nlist[node]["collectd"] = False
			else:
				self.nlist[node]["collectd"] = True
		except:
			self.nlock.release()
			res = str(sys.exc_info()[1])
			result['state'] = "Failed to open libvirt connection > "+res
			self.logger.log_error("Failed to open libvirt connection for %s: %s" % (node, res))
		
		self.logger.log_info("Adding "+node+" :"+result['state'])
		return result
	
	def add(self, sender, node, type, transport, description, options):
		"""
		Check if a node is already connected 
		and add it otherwise
		"""
		self.logger.log_debug("trying to add "+node)
		result = {}
		user = "root"
		transport = "ssh"
		system = "/system"
		if type == "kvm":
			driver = "qemu"
		elif type == "esx":
			transport = ""
			system = ""
			driver = type
		else:
			driver = type
		uri = driver+"+"+transport+"://"+user+"@"+node+system
		ip = ""
		do_key_exchange = False
		passwd = ""
		for option in options: 
			if "ssh" in option :
				transport = "ssh"
			elif "tls" in option:
				transport = "tls"
			elif "exchange_keys" in option:
				do_key_exchange = True
				args = option.split('=')
				passwd = args[1].strip()
			elif "ip" in option:
				args = option.split('=')
				ip = args[1].strip()
				args = option.split('=')
				ip = args[1].strip()
		if ip :
			valid = self.add_etchosts(node, ip)
			if not valid:
				result['state'] = "Failed: this node is already present in /etc/hosts, but with a different IP address."
				return result
		
		res = "Success"
		if do_key_exchange :
			try:
				res = self.exchange_keys(user, node, passwd, ip)
			except:
				res = "Failed"
		
		if res == "Failed":
			self.logger.log_error("Failed to exchange SSH keys")
			result['state'] = "Failed to exchange SSH keys"
			return result
		
		if transport != "":
			uri = driver+"+"+transport+"://"+user+"@"+node+system
		else :
			uri = driver+"://"+user+"@"+node+system
		
		conn_opened = "false"
		self.nlock.acquire_read()
		if self.nlist.has_key(node):
			conn_opened = self.nlist[node]["state"]
		self.nlock.release()
		
		if conn_opened != "open":
			self.logger.log_debug("trying to open connection to "+node)
			result = self.open_connection(node, uri, type)
			if "Failed" not in result['state']:
				self.db.add_node(node, ip, type, description)
				if type == "kvm":
					kvmtest = False
					self.nlock.acquire_read()
					conn = self.nlist[node]["connection"]
					self.nlock.release()
					xml = conn.getCapabilities()
					if "qemu-kvm" in xml:
						kvmtest = True
					if not kvmtest:
						self.remove(node)
						if ip:
							self.remove_etchosts(node, ip)
						result['state'] = "Failed: This node do not support KVM paravitualization."
			elif ip:
				self.remove_etchosts(node, ip)
		
		return result
	
	def test_connection(self, node, force):
		"""
		Test connection to a node
		"""
		result = {}
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				conn_opened = self.nlist[node]["state"]
				result['ip'] = self.nlist[node]["ip"]
				result['state'] = conn_opened
			else:
				result['state'] = "Failed: node not found"
			
			self.nlock.release()
			if force :
				try:
					self.close_connection(node)
				finally:
					time.sleep(5)
					conn_opened = "closed"
			
			if conn_opened != "open":
				nodeinfo = self.db.check_node(node)
				result = self.connect(nodeinfo['name'], nodeinfo['hypervisor'], "ssh", nodeinfo['ip'])
				if result["state"] == "connected":
					result['webshell'] = self.nlist[node]["webshell"]["port"]
					result['webshells'] = self.nlist[node]["webshell"]["sslport"]
			else:
				result['webshell'] = self.nlist[node]["webshell"]["port"]
				result['webshells'] = self.nlist[node]["webshell"]["sslport"]
		except:
			res = str(sys.exc_info()[1])
			result['state'] = "Failed to test connection to node "+node+": "+res
		return result
	
	def reconnect(self, node):
		"""
		Only used by nodemanger to reconnect a node 
		"""
		uri = self.nlist[node]["uri"]
		type = self.nlist[node]["type"]
		self.close_connection(node)
		time.sleep(5)
		res = self.open_connection(node, uri, type)
		result = {}
		result["state"] = "unreachable"
		if res["state"] == "connected":
			result["state"] = "reconnected"
			result["ip"] = res["ip"]
			result['webshell'] = self.nlist[node]["webshell"]["port"]
			result['webshells'] = self.nlist[node]["webshell"]["sslport"]
		else:
			result = res
		
		return result
	
	def remove(self, node):
		""" 
		Remove the connection to a node
		and stop its libvirtlistener session
		"""
		self.logger.log_debug("trying to remove "+node)
		result = ""
		self.nlock.acquire_read()
		if not self.nlist.has_key(node):
			self.nlock.release()
			inDb = self.db.check_node(node)
			if inDb["status"] == "successful":
				dbres = self.db.remove_node(node)
				return "node removed from database"
			else:
				self.logger.log_debug("node "+node+" not found")
				return "node not found"
		else:
			self.nlock.release()
			
		try:
			if self.nlist[node]["state"] == "open" :
				# Close connection
				self.close_connection(node)
			
			ip = self.nlist[node]["ip"]
			self.remove_etchosts(node, ip)
			# Remove VMs and Node from database
			dbres = self.db.remove_node(node)
		except:
			self.logger.log_warning("Unable to properly remove node "+node)
			res = str(sys.exc_info()[1])
			result = "Failed to remove node "+node+": "+res
		
		del self.nlist[node]
		self.logger.log_info("Node "+node+" has been removed")
		
		return result
	
	def close_connection(self, node):
		""" 
		close the connection to a node
		and stop its libvirtlistener session
		"""
		self.logger.log_debug("trying to close connection to "+node)
		result = ""
		self.nlock.acquire_read()
		if self.nlist.has_key(node):
			if self.nlist[node]["state"] != "open" :
				self.logger.log_info("libvirt connection already closed")
				self.nlock.release()
				return "libvirt connection already closed"
			else:
				conn = self.nlist[node]["connection"]
				self.nlock.release()
		else:
			self.nlock.release()
			return "node not found"
		
		try:
			if conn:
				self.logger.log_debug("Closing "+node+" connection")
				self.logger.log_debug("eventListener: "+str(self.eventListener))
				res = self.eventListener.unregister(conn)
				self.logger.log_info("Unregistered "+node+" events listener: %s" % res)
				self.nlock.acquire_write()
				self.nlist[node]["connection"] = None
				conn.close()
				del conn
				self.logger.log_debug("stopped "+node+" connection")
				self.nlist[node]["state"] = "closed"
				self.nlock.release()
				ip = self.nlist[node]["ip"]
				for pid in self.nlist[node]["webshell"]["pids"]:
					os.system("kill -9 %s" % str(pid))
				self.logger.log_info(node+" connection closed")
				result = "libvirt connection closed"
			else:
				self.nlist[node]["state"] = "closed"
			
		except:
			self.logger.log_error("Unable to properly close the connection")
			self.nlock.release()
			res = str(sys.exc_info()[1])
			self.logger.log_debug("Failed to close libvirt connection for %s: %s" % (node, res))
			result = "Failed to close libvirt connection > "+res
		
		self.logger.log_debug("Connection to "+node+" closed")
		
		return result
	
	def check_shellinabox(self, node):
		""" 
		Check if shellinabox is running on the node
		"""
		result = {}
		result["pids"] = []
		result["port"] = "0"
		result["sslport"] = "0"
		result["error"] = ""
		
		try:
			self.logger.log_debug("Checking if Shellinabox is installed")
			proc = subprocess.Popen(['ls','-a','/usr/sbin/shellinaboxd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			code = proc.wait()
			running = ""
			if code != 0:
				result["error"] = proc.stderr
				return result
			else:
				for aline in proc.stdout:
					running += aline+" "
			
			if running != "":
				self.logger.log_info("Shellinabox is running on "+node)
				result["running"] = {}
				if len(self.shellinabox_ports) > 0:
					lastport = self.shellinabox_ports[-1]
					newport = lastport + 1
				else:
					newport = 4201
				
				self.shellinabox_ports.append(newport)
				
				cmd = '/usr/sbin/shellinaboxd'
				cmd += ' --port='+str(newport)
				cmd += ' -b -t -c /var/lib/shellinabox'
				cmd += ' --pidfile=/etc/nodemanager/shellinabox/'+node+'.pid'
				cmd += ' -g shellinabox -u shellinabox ' 
				cmd += ' -s /:SSH:'+node
				self.logger.log_debug("Opening http port")
				os.system(cmd)
				
				proc = subprocess.Popen(['cat','/etc/nodemanager/shellinabox/'+node+'.pid'], stdout=subprocess.PIPE)
				retcode = proc.wait()
				line = ""
				for aline in proc.stdout:
					line+=aline+" "
				http_pid = line.strip()
				result["pids"].append(http_pid)
				
				## Configure NGINX SSL proxy
				f = open('/etc/nginx/conf.d/openkvi_nginx_ssl.conf', 'r')
				ssl_lines = f.readlines()
				f.close()
				to_add = True
				ref_line = "location /shellinabox/"+str(newport)+" {"
				for aline in ssl_lines:
					if ref_line in aline:
						to_add = False
						break
				
				if to_add:
					for i in range(len(ssl_lines)-1, -1, -1):
						if "}" in ssl_lines[i]:
							ssl_lines.pop(i)
							break
						
					ssl_lines.append("    location /shellinabox/"+str(newport)+" {\n")
					if self.logger.security != "low": 
						ssl_lines.append("        access_by_lua_file /etc/nginx/conf.d/authenticate.lua;\n")
					ssl_lines.append("        proxy_pass http://127.0.0.1:"+str(newport)+";\n")
					ssl_lines.append("    }\n")
					ssl_lines.append("}\n")
					
					f = open('/etc/nginx/conf.d/openkvi_nginx_ssl.conf', 'w')
					f.writelines(ssl_lines)
					f.close()
					os.system("service nginx reload")
				
				result["port"] = newport
				self.logger.log_info("Shellinabox tunnel opened on port "+str(newport))
		
		except:
			self.logger.log_warning("Shellinabox exception raised: %s" % str(sys.exc_info()[1]))
			result["error"] = "Error"
			return result
		
		return result
	
	def local_import(self, node, data, options):
		"""
		Set Time configuration
		"""
		result = []
		self.nlock.acquire_read()
		if self.nlist.has_key(node):
			conn = self.nlist[node]["connection"]
			self.nlock.release()
		else:
			self.nlock.release()
			return "node not found"
		
		vmlist = json.loads(data)
		for vm in vmlist:
			import_res = {}
			domain = conn.lookupByName(vm)
			xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
			infos = self.extract_vm_xml_info(xml)
			infos["server"] = node
			res = self.db.add_vm(infos)
			import_res["vm"] = vm
			import_res["status"] = res
			result.append(import_res)
		return result
	
	def extract_vm_xml_info(self, xml):
		infos = {}
		try:
			xmlDom = parseString(xml)
			nameNode = xmlDom.getElementsByTagName("name")[0]
			infos["name"] = self.getXmlText(nameNode.childNodes)
			infos["displayedname"] = infos["name"] 
			
			memNode = xmlDom.getElementsByTagName("memory")[0]
			infos["memory"] = int(self.getXmlText(memNode.childNodes))
			cpuNode = xmlDom.getElementsByTagName("vcpu")[0]
			infos["nbcpu"] = int(self.getXmlText(cpuNode.childNodes))
			infos["freqcpu"] = "0"
			osNode = xmlDom.getElementsByTagName("os")[0]
			osTypeNode = osNode.getElementsByTagName("type")[0]
			infos["arch"] = osTypeNode.getAttribute('arch')
			infos["cdrom"] = "not set"
			
			netNodes = xmlDom.getElementsByTagName("interface")
			network = ""
			for netNode in netNodes:
				type = netNode.getAttribute('type')
				if type == "bridge" :
					source = netNode.getElementsByTagName("source")[0]
					device = source.getAttribute('bridge')
				elif type == "network":
					source = netNode.getElementsByTagName("source")[0]
					device = source.getAttribute('network')
				elif type == "direct":
					source = netNode.getElementsByTagName("source")[0]
					device = source.getAttribute('dev')
				elif type == "ethernet":
					source = netNode.getElementsByTagName("target")[0]
					device = source.getAttribute('dev')
				elif type == "user":
					source = netNode.getElementsByTagName("mac")[0]
					device = source.getAttribute('address')
				if network == "":
					network = device
				else:
					network += ", "+device
			infos['network'] = network
			
			diskNodes = xmlDom.getElementsByTagName("disk")
			disks = ""
			for diskNode in diskNodes:
				type = diskNode.getAttribute('type')
				device = diskNode.getAttribute('device')
				if type == "file" and device == "disk" :
					source = diskNode.getElementsByTagName("source")[0]
					sourceAttr = source.getAttribute('file').split("/")
					if (len(sourceAttr) > 0):
						file = sourceAttr[-1]
					else:
						file = ""
					if disks == "":
						disks = file
					else:
						disks += ", "+file[0]
			
			infos['disks'] = disks
		
		except:
			self.logger.log_error("extract XML infos failed: %s" % str(sys.exc_info()[1]))
			return "Error: cannot extract XML infos: %s" % str(sys.exc_info()[1])
		
		return infos
	
	def getXmlText(self, nodelist):
		rc = []
		for node in nodelist:
			if node.nodeType == node.TEXT_NODE:
				rc.append(node.data)
		return ''.join(rc)
	
	def take_screenshots(self, stream, conn, options):
		""" 
		take screenshot of all running VMs defined on a node 
		It's only called by get_screenshots 
		"""
		for option in options:
			if "path" in option:
				args = option.split('=')
				path = args[1].strip()
			if "list" in option:
				args = option.split('=')
				strlist = args[1].strip()
				vmlist = strlist.split("::")
		result = []
		for vm in vmlist:
			try:
				time.sleep(1)
				infos = {}
				infos["name"] = vm
				domain = conn.lookupByName(vm)
				image = "/tmp/"+vm+".dat"
				if domain.isActive():
					try:
						path = self.vm_handle.get_screenshot(domain, conn, vm, options)
						infos["path"] = path
					except:
						self.logger.log_warning("Failed to get screenshot of %s")
						infos["path"] = "not supported :"+str(sys.exc_info()[1])
					
				else:
					self.logger.log_warning("Failed to get screenshot of %s: domain is not running" % vm)
					infos["path"] = "domain is not running"
			except:
				infos["path"] = "not supported :"+str(sys.exc_info()[1])
			result.append(infos)
		return result
	
	def get_vm_screenshots(self, node, options):
		""" 
		Open a new libvirt connection and
		call take_screenshots 
		""" 
		self.logger.log_debug("trying to get vmlist screenshot")
		self.nlock.acquire_read()
		if self.nlist.has_key(node):
			uri = self.nlist[node]["uri"]
			self.nlock.release()
		else:
			self.nlock.release()
			return "node not found"
		
		conn = libvirt.open(uri)
		stream = conn.newStream(0)
		try:
			result = self.take_screenshots(stream, conn, options)
			#stream.finish()
		except:
			self.logger.log_debug("screenshots error:  %s" % str(sys.exc_info()[1]))
			#stream.abort()
			result = "Error"
		finally:
			self.logger.log_debug("remove temporary connection to "+node)
		
		del conn
		self.logger.log_debug("Got all screenshot for "+node)
		return result
	
	def get_vm_list(self, node):
		""" Get list a VMs defined by libvirt on a node """
		self.logger.log_debug("trying get vm list of "+node)
		result = []
		self.nlock.acquire_read()
		if self.nlist.has_key(node):
			conn = self.nlist[node]["connection"]
			self.nlock.release()
		else:
			self.nlock.release()
			return "node not found"
		try :
			idList = conn.listDomainsID()
			for id in idList:
				vmInfos = {}
				domain = conn.lookupByID(id)
				[strState, maxmem, mem, ncpu, cputime] = self.vm_handle.info(domain)
				vmInfos["vm"] = domain.name()
				vmInfos["state"] = strState
				vmInfos["ncpu"] = ncpu
				result.append(vmInfos)
				
			vmList = conn.listDefinedDomains()
			for aVm in vmList:
				vmInfos = {}
				try:
					domain = conn.lookupByName(aVm)
					[strState, maxmem, mem, ncpu, cputime] = self.vm_handle.info(domain)
					vmInfos["state"] = strState
					vmInfos["ncpu"] = ncpu
				except:
					vmInfos["state"] = "not found"
					vmInfos["ncpu"] = 0
				finally:
					vmInfos["vm"] = aVm
					result.append(vmInfos)
			
			self.logger.log_debug("Got vm list from "+node)
		except:
			self.logger.log_warning("Error getting vm list: %s" % str(sys.exc_info()[1]))
			result = "Error"
		
		return result
	
	def get_all_nodes_infos(self):
		""" 
		Get hardware, system en ressources information for all nodes
		"""
		result = {}
		result["error"] = ""
		thread_lst = []
		try:
			def threadGetNodeInfo(node, result):
				result[node] = {}
				general = {}
				general["type"] = self.nlist[node]["type"]
				general["ip"] = self.nlist[node]["ip"]
				general["vms"] = {}
				general["state"] = self.nlist[node]["state"]
			
				if general["state"] != "open":
					general["active"] = False
				else:
					general["active"] = True
					self.get_system(node)
					self.get_info(node, [])
					self.get_node_usage(node, [])
					vmListInfo = self.get_vm_list(node)
				
					knownVmList = []
					allvmlist = self.db.list_vms()
					for vm in allvmlist['vms']:
						if vm['server'] == node:
							knownVmList.append(vm['name'])
					
					vm_count = len(vmListInfo)
					active_vms = 0
					vcpus = 0
					for entry in vmListInfo:
						if isinstance(entry, dict) and entry.has_key("state"):
							if entry["state"] == "running":
								active_vms += 1
								vcpus += entry["ncpu"]
				
					general["vms"]["running"] = active_vms
					general["vms"]["total"] = vm_count
					general["vms"]["vcpus"] = vcpus
					general["vms"]["list"] = knownVmList
				
					result[node]["hardware"] = self.nlist[node]["hardware"]
					result[node]["system"] = self.nlist[node]["system"]
					result[node]["ressources"] = self.nlist[node]["ressources"]
				result[node]["general"] = general
			
			for node in self.nlist.keys():
				t = threading.Thread(target=threadGetNodeInfo, args=(node, result))
				thread_lst.append(t)
			for thread in thread_lst:
				thread.start()
			for thread in thread_lst:
				thread.join()
			
		except:
			self.logger.log_error("Failed to get all nodes information: %s" % str(sys.exc_info()[1]))
			result["error"] = "Error: cannot get all nodes informantion: %s" % str(sys.exc_info()[1])
		return result
	
	def get_capabilities(self, node, options):
		"""
		Get Virtualization capabilities of a node
		such as supported architectures and
		virtualization technologie used
		"""
		self.logger.log_debug("trying to get capabilities of "+node)
		path = "/tmp/"+node+"_capabilities.xml"
		try:
			for option in options: 
				if "path" in option:
					args = option.split('=')
					path = args[1].strip()
					#os.system("sudo -u tomcat mkdir -p "+path)
					if not os.path.exists(path):
						os.makedirs(path)
						uid = pwd.getpwnam("tomcat").pw_uid
						gid = grp.getgrnam("tomcat").gr_gid
						os.chown(path+"/../", uid, gid)
						os.chown(path, uid, gid)
		except:
			self.logger.log_error("Failed to get capabilities for %s: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot get %s capabilities: %s" % (node, str(sys.exc_info()[1]))
		
		self.logger.log_debug("{get_capabilities} capa path: "+path)
		
		result = ""
		self.nlock.acquire_read()
		if self.nlist.has_key(node):
			conn = self.nlist[node]["connection"]
			type = self.nlist[node]["type"]
			self.nlock.release()
		else:
			self.nlock.release()
			self.logger.log_debug(node+" not found")
			return "node not found"
		
		try:
			xml = conn.getCapabilities()
			self.logger.log_debug("{get_capabilities} xml: "+xml)
			f = open(path+"/capabilities.xml", 'w')
			f.write(xml)
			f.close()
			os.system("chmod 666 "+path+"/capabilities.xml")
		except:
			self.logger.log_error("Failed to get capabilities for %s: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot get %s capabilities: %s" % (node, str(sys.exc_info()[1]))
		
		infos = []
		self.logger.log_debug("type is : %s" % type)
		try:
			if type == "kvm":
				#cmd = 'ssh -x root@'+node+' "ls /usr/share/qemu-kvm/keymaps/ | grep -v common | grep -v modifiers"'
				#input = os.popen(cmd, 'r')
				#lines = input.readlines()
				#input.close()
				
				cmd = 'ls /usr/share/qemu-kvm/keymaps/ | grep -v common | grep -v modifiers'
				res, error = ssh.run(node, cmd)
				lines = ','.join(res)
				f = open(path+"/keymaps.lst", 'w')
				f.write(lines)
				f.close()
				os.system("chmod 666 "+path+"/keymaps.lst")
			else:
				f = open(path+"/keymaps.lst", 'w')
				f.write("[]")
				f.close()
				os.system("chmod 666 "+path+"/keymaps.lst")
		
		except:
			self.logger.log_warning("Failed to get keymap info for %s: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot get %s keymap info: %s" % (node, str(sys.exc_info()[1]))
		
		self.logger.log_debug("Got capabilities & keymap from "+node)
		return "done"
	
	def get_system(self, node):
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				conn = self.nlist[node]["connection"]
				self.nlock.release()
			else:
				self.nlock.release()
		
			infos = {}
			xml = conn.getSysinfo(0)
			xmlDom = parseString(xml)
			domSystem = xmlDom.getElementsByTagName("system")[0]
			systemEntries = domSystem.getElementsByTagName("entry")
			for systemEntry in systemEntries: 
				name = systemEntry.getAttribute('name')
				content = systemEntry.firstChild.data
				infos[name] = content
			
			self.nlist[node]["hardware"] = infos
		except:
			infos = {}
			infos['manufacturer'] = "Unknown. An error occured."
			infos['serial'] = "Unknown. An error occured."
			infos['product'] = "Unknown. An error occured."
			infos['version'] = "Unknown. An error occured."
		
		return infos
	
	def get_info(self, node, options):
		"""
		Get general system info
		"""
		path = "/tmp/"+node+"_info.xml"
		infos = {}
		result = {}
		for option in options: 
			if "path" in option:
				args = option.split('=')
				path = args[1].strip()
		
		self.nlock.acquire_read()
		if self.nlist.has_key(node):
			conn = self.nlist[node]["connection"]
			self.nlock.release()
		else:
			self.nlock.release()
			return "node not found"
		
		try:
			now = time.time()
			if self.nlist[node].has_key("system") and self.nlist[node]["system"].has_key("last"):
				last = self.nlist[node]["system"]["last"]
			else:
				last = 0
			
			elapsed = now - last
			# re fetch info every 15 min min
			if last == 0 or elapsed > 900:
				res = conn.getInfo()
				infos["arch"] = res[0]
				infos["memory"] = res[1]
				infos["cpus"] = res[2]
				infos["mhz"] = res[3]
				infos["nodes"] = res[4]
				infos["sockets"] = res[5]
				infos["cores"] = res[6]
				infos["threads"] = res[7]
				
				
				cmd = 'tail -n1 /etc/redhat-release 2>/dev/null | sed -e "s/\[.*//" | sed -e "s/ *$//"'
				lst_res, error = ssh.run(node, cmd)
				os_name = ' '.join(lst_res)
				cmd = 'tail -n1 /etc/redhat-release 2>/dev/null | sed -e "s/.*version: *//" | sed -e "s/\(,\| \|]\).*//"'
				lst_res, error = ssh.run(node, cmd)
				os_ver = ' '.join(lst_res)
				if os_ver:
					os_name += ", version: "+os_ver.strip()
				infos["os"] = os_name
				
				self.nlist[node]["system"] = infos.copy()
				self.nlist[node]["system"]["last"] = now
			
			result["system"] = self.nlist[node]["system"].copy()
			result["sysinfo"] = self.nlist[node]["hardware"].copy()
			
		except:
			self.logger.log_error("Failed to get %s infos: %s" % (node, str(sys.exc_info()[1])))
			#return "Error: cannot get %s info: %s" % (node, str(sys.exc_info()[1]))
		return result
	
	def get_node_usage(self, node, options):
		"""
		Get CPU and Memory usage on node
		"""
		result = {}
		try:
			infos = {}
			storages = []
			
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				conn = self.nlist[node]["connection"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			
			result["storages"] = []
			now = time.time()
			if self.nlist[node].has_key("ressources") and self.nlist[node]["ressources"].has_key("last"):
				last = self.nlist[node]["ressources"]["last"]
			else:
				last = 0
				self.nlist[node]["ressources"] = {}
			
			elapsed = now - last
			# re fetch info every 5 min min
			if last == 0 or elapsed > 60:
				cpu_usage = self.get_cpu_usage(conn)
				mem_usage = self.get_mem_usage(conn, node)
				uptime_info = self.get_uptime(node)
				result["storages"], error = self.nlist[node]["pools"].getPoolsConfig()
				
				result["cpu"] = cpu_usage
				result["memory"] = mem_usage
				result["uptime"] = uptime_info["uptime"]
				result["load"] = uptime_info["load"]
				self.nlist[node]["ressources"] = result
				self.nlist[node]["ressources"]["last"] = now
			else:
				result = self.nlist[node]["ressources"].copy()
			
		except:
			self.logger.log_error("Failed to get %s ressources: %s" % (node, str(sys.exc_info()[1])))
		return result
	
	def get_cpu_usage(self, conn):
		"""
		Get CPU usage on node in percent
		"""
		try:
			prev_idle = 0
			prev_total = 0
			for num in range(2):
				cpu_info = conn.getCPUStats(-1,0)
				idle = cpu_info.values()[1]
				total = sum(cpu_info.values())
				diff_idle = idle - prev_idle
				diff_total = total - prev_total
				diff_usage = (1000 * (diff_total - diff_idle) / diff_total + 5) / 10
				prev_total = total
				prev_idle = idle
				if num == 0: 
					time.sleep(1)
				else:
					if diff_usage < 0:
						diff_usage = 0
			return diff_usage
			
		except:
			self.logger.log_error("Failed to get cpu infos: %s" % str(sys.exc_info()[1]))
			return "Error: cannot get cpu info: %s" % str(sys.exc_info()[1])
	
	def get_mem_usage(self, conn, node):
		"""
		Get memory usage on node in percent
		"""
		infos = {}
		try:
			tot_mem = conn.getInfo()[1]
			cmd = 'free -m | grep "cache:" | awk \'{print $3,$4}\''
			res, error = ssh.run(node, cmd)
			if not res:
				cmd = 'free -m | grep "Mem:" | awk \'{print $3,$7}\''
				res, error = ssh.run(node, cmd)
			
			memInfo = ' '.join(res)
			args = memInfo.split(' ')
			
			self.logger.log_debug("{get_mem_usage] memory infos: %s" % memInfo)
			#free = conn.getFreeMemory()
			#infos["free"] = round((free / 1048576), 0)
			infos["free"] = args[1].strip()
			infos["used"] = args[0].strip()
			infos["total"] = str(tot_mem)
			
			return infos
			
		except:
			self.logger.log_error("Failed to get memory infos: %s" % str(sys.exc_info()[1]))
			return "Error: cannot get memory info: %s" % str(sys.exc_info()[1])
	
	def get_uptime(self, node):
		"""
		Get uptime infos 
		"""
		infos = {}
		infos["uptime"] = ""
		infos["error"] = ""
		try:
			cmd = 'uptime'
			res, error = ssh.run(node, cmd)
			upInfo = ' '.join(res)
			upInfo = upInfo.replace('  ', ' ')
			args0 = upInfo.split('user')
			args1 = args0[0].strip().split('up')
			args2 = args0[1].strip().split(':')
			
			args_uptime = args1[1].strip().split(' ')
			
			del args_uptime[len(args_uptime) - 1]
			years = 0
			days = 0
			min = 0
			hours = 0
			i = 0
			while len(args_uptime) > 0:
				if ":" in args_uptime[0]:
					args_hours = args_uptime[0].split(":")
					hours = int(args_hours[0])
					min = args_hours[1].replace(",", "")
					del args_uptime[0]
				elif "year" in args_uptime[1]:
					years = int(args_uptime[0])
					del args_uptime[1]
					del args_uptime[0]
				elif "day" in args_uptime[1]:
					days = int(args_uptime[0])
					del args_uptime[1]
					del args_uptime[0]
				elif "min" in args_uptime[1]:
					min = args_uptime[0]
					del args_uptime[1]
					del args_uptime[0]
				i += 1
				if i > 6:
					# prevent infinite loop
					break
			
			syears = "%s year" % years
			if years > 1:
				syears += "s"
			
			sdays = "%s day" % days
			if days > 1:
				sdays += "s"
			
			shours = "%s hour" % hours
			if hours > 1:
				shours += "s"
			
			if years > 0:
				uptime = "%s, %s, %s, %s min." % (syears, sdays, shours, min)
			else:
				uptime = "%s, %s, %s min." % (sdays, shours, min)
			infos["uptime"] = uptime
			
			args_loads = args2[1].strip().split(' ')
			infos["load"] = args_loads[2].strip()
			
		except:
			self.logger.log_error("Failed to get uptime infos: %s" % str(sys.exc_info()[1]))
			infos["error"] = "Error: cannot get uptime info: %s" % str(sys.exc_info()[1])
		return infos
	
	def get_node_time(self, node, options):
		"""
		Get Time configuration
		"""
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				conn = self.nlist[node]["connection"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			
			result = {}
			result["servers"] = []
			result["other"] = []
			lst_res = []
			error = ""
			
			# Get Date and Time
			cmd='date +"%a %d %b %Y - %T"'
			lst_res, error = ssh.run(node, cmd)
			result["date"] = ' '.join(lst_res)
				
			cmd='date +"%Y %m %d %T %:::z"'
			lst_res, error = ssh.run(node, cmd)
			result["time"] = ' '.join(lst_res)
			
			cmd='head -n1 /etc/sysconfig/clock | sed -e "s/.*=//"'
			lst_res, error = ssh.run(node, cmd)
			result["timezone"] = ' '.join(lst_res)
			
			cmd='pgrep "^ntpd$"'
			lst_res, error = ssh.run(node, cmd)
			res = ' '.join(lst_res)
			if res.strip() == "" :
				line = "stopped"
			else :
				line = "running"
			result["ntpd"] = line
				
			cmd = 'chkconfig --list ntpd | sed -e "s/.*3://" | sed -e "s/[[:blank:]].*//"'
			lst_res, error = ssh.run(node, cmd)
			result["ntpd_autostart"] = ' '.join(lst_res)
			
			cmd = 'cat /etc/ntp.conf | grep "^server " | sed -e "s/#.*//" | sed -e "s/^server *//"'
			lst_res, error = ssh.run(node, cmd)
			result["servers"] = lst_res
			
			cmd = 'cat /etc/ntp.conf | grep -v "^#" | grep -v "^server" | grep -v "^$"'
			lst_res, error = ssh.run(node, cmd)
			result["other"] = lst_res
			
			return result
		except:
			self.logger.log_error("Failed to get %s time config: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot get %s time config: %s" % (node, str(sys.exc_info()[1]))
	
	def set_node_time(self, node, data, options):
		"""
		Set Time configuration
		"""
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				conn = self.nlist[node]["connection"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
				
			result = "Successful"
			self.logger.log_debug("Set time: %s" % data)
			config = json.loads(data)
			if config["date"] :
				cmd = 'date --set="'+config["date"]+'" +"%a %d %b %Y"'
				res, error = ssh.run(node, cmd)
				
			if config["time"] :
				cmd = 'date --set="'+config["time"]+'"'
				res, error = ssh.run(node, cmd)
				
			if config["timezone"] :
				cmd = 'echo "ZONE=\"'+config["timezone"]+'\"" > /etc/sysconfig/clock'
				res, error = ssh.run(node, cmd)
				cmd = 'rm -f /etc/localtime; ln -sf /usr/share/zoneinfo/'+config["timezone"]+' /etc/localtime'
				res, error = ssh.run(node, cmd)
				
			if config["ntp"] :
				cmd = 'chkconfig --add ntpd'
				res, error = ssh.run(node, cmd)
				cmd = 'chkconfig --level 345 ntpd on'
				res, error = ssh.run(node, cmd)
				cmd = 'service ntpd stop'
				res, error = ssh.run(node, cmd)
				cmd = 'ntpdate '+config["ntp_server"]
				res, error = ssh.run(node, cmd)
				if error:
					result = "Failed to synchronize with primary server"
				
				cmd = 'cp --remove-destination /etc/ntp.conf /etc/ntp.conf.backup'
				res, error = ssh.run(node, cmd)
				
				#perl -p -i -e "s/^server 62.161.167.251.*$//" ntp.conf
				cmd = 'perl -p -i -e "s/^server '+config["ntp_server"]+'.*$//" /etc/ntp.conf'
				res, error = ssh.run(node, cmd)
				
				cmd = 'sed -e "0,/^server .*/{s/^server \(.*\)/server '+config["ntp_server"]+'\\nserver \\1/}" '
				cmd += '/etc/ntp.conf > /etc/ntp.conf.tmp'
				res, error = ssh.run(node, cmd)
				
				# Check that there is at least one server configured:
				cmd = 'if [ ! "`grep "^server [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" /etc/ntp.conf`" ]'
				cmd += '; then echo "server '+config["ntp_server"]+'" >> /etc/ntp.conf.tmp; fi'
				res, error = ssh.run(node, cmd)
				
				# Remove duplicate blank lines
				cmd = 'awk \'/^$/{ if (! blank++) print; next } { blank=0; print }\' /etc/ntp.conf.tmp > /etc/ntp.conf; rm -f /etc/ntp.conf.tmp'
				res, error = ssh.run(node, cmd)
				
				cmd = 'service ntpd start'
				res, error = ssh.run(node, cmd)
				cmd = 'service ntpd status'
				res, error = ssh.run(node, cmd)
				if error:
					result = "Failed to configure NTP service"
			else:
				# Deactivate NTP
				cmd = 'chkconfig --del ntpd'
				res, error = ssh.run(node, cmd)
				cmd = 'service ntpd stop'
				res, error = ssh.run(node, cmd)
			
			return result
		except:
			self.logger.log_error("Failed to set %s time config: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot set %s time config: %s" % (node, str(sys.exc_info()[1]))
	
	def set_node_timeserver(self, node, data, options):
		"""
		Set Time configuration
		"""
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				conn = self.nlist[node]["connection"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			
			result = "Successful"
			config = json.loads(data)
			#Remove all previous NTP servers
			cmd = 'perl -p -i -e "s/^server .*$//" /etc/ntp.conf'
			lst_res, error = ssh.run(node, cmd)
			
			line = ''
			for aServer in config["ntp_servers"]:
				line += "server "+aServer+'\n'
			
			cmd = 'echo "'+line+'" >> /etc/ntp.conf'
			lst_res, error = ssh.run(node, cmd)
			
			return result
		except:
			self.logger.log_error("Failed to set %s ntp servers config: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot set %s ntp servers config: %s" % (node, str(sys.exc_info()[1]))
	
	def set_node_timemisc(self, node, data, options):
		"""
		Set Time configuration
		"""
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				conn = self.nlist[node]["connection"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			
			result = "Successful"
			config = json.loads(data)
			line = ''
			for aServer in config["ntp_servers"]:
				line += "server "+aServer+'\n'
			line += config["misc"]
			cmd = 'echo \''+line+'\' > /etc/ntp.conf'
			lst_res, error = ssh.run(node, cmd)
			
			cmd = 'service ntpd status'
			lst_res, error = ssh.run(node, cmd)
			if len(error) == 0:
				cmd = 'service ntpd restart'
				lst_res, error = ssh.run(node, cmd)
				cmd = 'service ntpd status'
				lst_res, error = ssh.run(node, cmd)
				if error:
					result = "Failed to configure NTP service."
			else:
				result = "NTP service is not running."
				
			
			return result
		except:
			self.logger.log_error("Failed to set %s time config: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot set %s time config: %s" % (node, str(sys.exc_info()[1]))
	
	def get_node_snmp(self, node, options):
		"""
		Get Time configuration
		"""
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				conn = self.nlist[node]["connection"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			
			result = {}
			lst_res = []
			error = ""
			
			cmd='service snmpd status'
			lst_res, error = ssh.run(node, cmd)
			res = ' '.join(lst_res)
			if "snmpd" in res:
				status = re.sub('\.\.\.$', '', re.sub('snmpd .* is ', '', res))
			else:
				status = "unrecognized service"
			result["service"] = status
			
			cmd = 'chkconfig --list snmpd | sed -e "s/.*3://" | sed -e "s/[[:blank:]].*//"'
			lst_res, error = ssh.run(node, cmd)
			result["autostart"] = ' '.join(lst_res)
			
			cmd = 'grep "trapsink\|trap2sink\|informsink" /etc/snmp/snmpd.conf  | sed -e "s/.*sink \(.*\) .*/\\1/"'
			lst_res, error = ssh.run(node, cmd)
			server = ""
			for line in lst_res:
				if not server:
					server = line.strip()
				elif server != line.strip():
					server = "unset"
			if server == "":
				server = "unset"
			result["server"] = server
			
			result["agent"] = {}
			result["agent"]["name"] = "unknown"
			result["agent"]["version"] = "not installed"
			# Both OpenIPMI and freeipmi are needed
			agent = "OpenIPMI freeipmi"
			agent_daemon = "ipmi"
			for case in switch(self.nlist[node]['hardware']['manufacturer']):
				if case("HP"):
					agent = "hp-health"
					agent_daemon = "hp-health"
			
			# Only keep first package as a reference
			result["agent"]["name"] = re.sub(' .*', '', agent)
			packages = re.sub(' ', '\|', agent)
			cmd = 'rpm -q '+agent+' | sed -e "s/'+packages+'//" |  sed -e "s/.x86_64//" | sed -e "s/^-//"'
			lst_res, error = ssh.run(node, cmd)
			if error:
				result["agent"]["version"] = "not installed"
			elif 'is not installed' in ''.join(lst_res):
				result["agent"]["version"] = "not installed"
				for agent_version in lst_res:
					if 'is not installed' in agent_version:
						result["agent"]["name"] = re.sub(" is not installed.*", "", agent_version).replace("package ", "")
						break
			else:
				result["agent"]["version"] = lst_res[0]
			
			cmd='service '+agent_daemon+' status'
			lst_res, error = ssh.run(node, cmd)
			if error:
				res = error
			else:
				res = lst_res[len(lst_res)-1]
			if "does not exist" in res or "is stopped" in res:
				agent_status = "stopped"
			else :
				agent_status = "running"
			result["agent"]["service"] = agent_status
			
			cmd = 'chkconfig --list '+agent_daemon+' | sed -e "s/.*3://" | sed -e "s/[[:blank:]].*//"'
			lst_res, error = ssh.run(node, cmd)
			result["agent"]["autostart"] = ' '.join(lst_res)
			
			return result
		except:
			self.logger.log_error("Failed to get %s snmpd config: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot get %s snmpd config: %s" % (node, str(sys.exc_info()[1]))
	
	def set_node_snmp_config(self, node, data):
		""" 
		Set SNMP configuration
		"""
		res = "successful"
		try:
			snmp_data = json.loads(data)
			if snmp_data['autostart']:
				cmd = 'chkconfig --level 345 snmpd on'
			else:
				cmd = 'chkconfig --level 345 snmpd off'
			lst_res, error = ssh.run(node, cmd)
			if error:
				return "Error "+error
			
			# Test SNMP server 
			cmd = 'ping -c1 '+snmp_data['server']
			lst_res, error = ssh.run(node, cmd)
			for line in lst_res:
				if "100% packet loss" in line:
					return "Error: remote server "+snmp_data['server']+" is not reachable"
			
			str_input = "# Added by OpenKVI on $(date)\n"
			for case in switch(self.nlist[node]['hardware']['manufacturer']):
				if case("HP"):
					str_input += "dlmod cmaX /usr/lib64/libcmaX64.so\n"
			str_input += "rwcommunity  public "+snmp_data['server']+"\n"
			str_input += "rocommunity  public "+snmp_data['server']+"\n"
			str_input += "trapcommunity public\n"
			str_input += "trapsink "+snmp_data['server']+" public\n"
			str_input += "trap2sink "+snmp_data['server']+" public\n"
			str_input += "informsink "+snmp_data['server']+" public\n"
			str_input += "# ---------------------- END --------------------"
			
			ignore_header = "^#.* HP Insight\|^#.* OpenKVI\|^# --* END"
			ignore_cfg = "^dlmod cmaX\|^rwcommunity\|^rocommunity\|^trapcommunity\|^trapsink\|^trap2sink\|^informsink"
			cmd = 'cat /etc/snmp/snmpd.conf | grep -v "'+ignore_cfg+'" | grep -v "'+ignore_header+'" > /tmp/snmpd.conf'
			lst_res, error = ssh.run(node, cmd)
			
			cmd = 'echo -e "'+str_input+'" > /tmp/snmp.head'
			lst_res, error = ssh.run(node, cmd)
			
			cmd = 'rm -f /etc/snmp/snmpd.conf; cat /tmp/snmp.head /tmp/snmpd.conf > /etc/snmp/snmpd.conf'
			lst_res, error = ssh.run(node, cmd)
			if error:
				return "Error: "+error

			cmd = 'rm -f /tmp/snmp.head /tmp/snmpd.conf'
			lst_res, error = ssh.run(node, cmd)
			
			if snmp_data['run']:
				cmd = 'service snmpd restart'
			else:
				cmd = 'service snmpd stop'
			lst_res, error = ssh.run(node, cmd)
			if error:
				return "Error: "+error
			
			res = self.restart_ipmi_agent(node, True)
			return res
			
			return res
		except:
			self.logger.log_error("Failed to set %s snmpd config: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot set %s snmpd config: %s" % (node, str(sys.exc_info()[1]))
	
	def restart_ipmi_agent(self, node, restart):
		""" 
		Restart IPMI agent to take modifcations into account
		"""
		res = "successful"
		try:
			if restart:
				cmd_state = 'restart'
				cmd = "service ipmi "+cmd_state+"; service ipmievd "+cmd_state
			else:
				cmd_state = 'stop'
				cmd = "service ipmievd "+cmd_state+"; service ipmi "+cmd_state
			for case in switch(self.nlist[node]['hardware']['manufacturer']):
				if case("HP"):
					cmd = "service hp-health "+cmd_state+"; service hp-snmp-agents "+cmd_state
			lst_res, error = ssh.run(node, cmd)
			if error:
				res = "Error: "+error
			return res
		except:
			self.logger.log_error("Failed to restart %s ipmi agent: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot restart %s ipmi agent: %s" % (node, str(sys.exc_info()[1]))
		
	def set_node_ipmi_config(self, node, data):
		""" 
		Set IPMI configuration
		"""
		res = "successful"
		try:
			ipmi_data = json.loads(data)
			#cmd = 'chkconfig --level 345 ipmid off'
			if ipmi_data['autostart']:
				chk_state = 'on'
			else:
				chk_state = 'off'
			
			cmd = "chkconfig --level 345 ipmi "+chk_state+"; chkconfig --level 345 ipmievd "+chk_state
			for case in switch(self.nlist[node]['hardware']['manufacturer']):
				if case("HP"):
					cmd = "chkconfig --level 345 hp-health "+chk_state+"; chkconfig --level 345 hp-snmp-agents "+chk_state
			lst_res, error = ssh.run(node, cmd)
			if error:
				return "Error "+error
			
			res = self.restart_ipmi_agent(node, ipmi_data['run'])
			return res
		except:
			self.logger.log_error("Failed to set %s ipmi config: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot set %s ipmi config: %s" % (node, str(sys.exc_info()[1]))
	
	def get_node_hardware_events(self, node):
		"""
		Retrieve Hardware events from /var/log/messages
		"""
		lst_res = []
		try:
			hel = self.get_node_snmp(node, None)
			
			if hel["agent"]["name"] == "unknown" or hel["agent"]["version"] == "not installed":
				now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
				lst_res.append(now+" ::[CRITICAL]:: Hardware monitoring agent is not installed")
			elif hel["agent"]["service"] == "stopped":
				now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
				lst_res.append(now+" ::[CRITICAL]:: Hardware monitoring agent is not running")
			else:
				# We first get infos from old messages files
				cmd = 'grep "ipmievd" /var/log/messages-* 2>/dev/null | sed -e "s/ipmievd:/HEL:/" | sed -e "s/$(hostname) //"'
			
				for case in switch(self.nlist[node]['hardware']['manufacturer']):
					if case("HP"):
						cmd = 'grep "hpasmlited" /var/log/messages-* 2>/dev/null | sed -e "s/hpasmlited\[.*\]:/HEL:/" | sed -e "s/$(hostname) //"'
				
				cmd += ' | sed -e "s/HEL: \\(CRITICAL\\|WARNING\\|NOTICE\\):/::[\\1]::/" | sed -e "s/HEL:/::[INFOS]::/"'
				lst_res, error = ssh.run(node, cmd)
				if error:
					lst_res.append("Error: "+error)
				
				# Then in the current
				cmd = 'grep "ipmievd" /var/log/messages 2>/dev/null | sed -e "s/ipmievd:/HEL:/" | sed -e "s/$(hostname) //"'
			
				for case in switch(self.nlist[node]['hardware']['manufacturer']):
					if case("HP"):
						cmd = 'grep "hpasmlited" /var/log/messages 2>/dev/null | sed -e "s/hpasmlited\[.*\]:/HEL:/" | sed -e "s/$(hostname) //"'
				
				cmd += ' | sed -e "s/HEL: \\(CRITICAL\\|WARNING\\|NOTICE\\):/::[\\1]::/" | sed -e "s/HEL:/::[INFOS]::/"'
				lst_res2, error = ssh.run(node, cmd)
				if error:
					lst_res.append("Error: "+error)
				else:
					lst_res.extend(lst_res2)
			
			return lst_res
		except:
			self.logger.log_error("Failed to get %s hardware events: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot get %s hardware events: %s" % (node, str(sys.exc_info()[1]))
	
	def check_node_collectd(self, node):
		""" 
		get Node's collectd data
		"""
		res = ""
		try:
			cmd = 'rpm -q collectd | sed -e "s/collectd-//" | sed -e "s/-.*//"'
			lst_res, error = ssh.run(node, cmd)
			if error:
				return "Error: "+error
			else:
				collectd_version = ''.join(lst_res)
			if "not installed" in collectd_version:
				return "Error: collected is not installed, please upgrade your KVM server with the latest NetOS 6 version"
			
			vers = collectd_version.split('.')
			if vers[0] >= 5 and vers[1] >= 4:
				# Check that cpu aggregation is configured
				cmd = 'grep "^LoadPlugin aggregation\|^FQDNLookup *false\|^LoadPlugin processes" /etc/collectd.conf'
				lst_res, error = ssh.run(node, cmd)
				if error:
					return "Error: "+error
				elif len(lst_res) != 3:
					err = rsync.send("/usr/local/openkvi/collectd.conf", "/etc/", node)
					if err:
						return err
					
					cmd = "service collectd restart"
					lst_res, error = ssh.run(node, cmd)
					if error:
						return "Error: cannot start collectd service: "+error
					else:
						cmd = "chkconfig --level 345 collectd on"
						lst_res, error = ssh.run(node, cmd)
						return "Warning: collectd service has been restarted, please try again later"
					
				# Get service status
				cmd = "service collectd status"
				lst_res, error = ssh.run(node, cmd)
				if error:
					return "Error: "+error
				else:
					collectd_service = ''.join(lst_res)
				
				if "stopped" in collectd_service:
					cmd = "service collectd start"
					lst_res, error = ssh.run(node, cmd)
					if error:
						return "Error: cannot start collectd service: "+error
					else:
						cmd = "chkconfig --level 345 collectd on"
						lst_res, error = ssh.run(node, cmd)
						return "Warning: collectd service was not started, please try again later"
				
			else:
				res = "Error: collected is not up to date, please upgrade your KVM server with the latest NetOS 6 version"
		except:
			self.logger.log_error("Failed to get %s performance data: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot get %s performance data: %s" % (node, str(sys.exc_info()[1]))
		return res
	
	def get_node_collectd_data(self, node, path):
		""" 
		get Node's collectd data
		"""
		res = {}
		res['conf'] = {}
		res['error'] = ""
		try:
			if path[len(path)-1] != "/":
				path += "/"
				
			if not os.path.exists(path+"/"+node):
				os.makedirs(path+"/"+node, 0755)
			
			if not self.nlist[node]["collectd"]:
				err = self.check_node_collectd(node)
				if err:
					self.nlist[node]["collectd"] = False
					res['error'] = err
					return res
				else:
					self.nlist[node]["collectd"] = True
			
			cmd = "hostname"
			lst_res, error = ssh.run(node, cmd)
			REMOTE_HOSTNAME = ''.join(lst_res)
			res['conf']['host'] = REMOTE_HOSTNAME
			src = "/var/lib/collectd/%s/" % REMOTE_HOSTNAME
			dst = "%s%s/" % (path, REMOTE_HOSTNAME)
			# rsync remote data
			err = rsync.get(src, dst, node)
			if err:
				res['error'] = err
				return res
			
			dir_content = os.listdir(dst)
			ccount = 0
			eth_count = 0
			for entry in dir_content:
				if re.match("^cpu-", entry):
					ccount += 1
				elif re.match("^processes-qemu-kvm", entry):
					res['conf']['qemukvm'] = True
				elif re.match("^interface-eth", entry):
					eth_count += 1
				
			res['conf']['cpus'] = ccount
			res['conf']['eth'] = eth_count
			
		except:
			self.logger.log_error("Failed to get %s performance data: %s" % (node, str(sys.exc_info()[1])))
			res['error'] = "Error: cannot get %s performance data: %s" % (node, str(sys.exc_info()[1]))
			return res
		
		return res
	
	def get_node_logs(self, node):
		""" 
		Retreive node's log files
		"""
		res = {}
		res['path'] = "/opt/virtualization/openkvi/%s/" % (node)
		res['files'] = []
		res['error'] = ""
		try:
			src = "/var/log/messages"
			dst = res['path']
			# rsync remote data
			err = rsync.get(src, dst, node)
			if err:
				res['error'] = err
				return res
			else:
				res['files'].append("messages")
			# Enable tomcat to read logs
			os.system("chown -R root.tomcat %s" % res['path'])
			os.system("chmod 754 %s" % res['path'])
			os.system("chmod 744 %s/*" % res['path'])
			cmd = "hostname"
			lst_res, error = ssh.run(node, cmd)
			REMOTE_HOSTNAME = ''.join(lst_res)
			res['host'] = REMOTE_HOSTNAME
		except:
			self.logger.log_error("Failed to get %s log files: %s" % (node, str(sys.exc_info()[1])))
			res['error'] = "Error: cannot get %s log files: %s" % (node, str(sys.exc_info()[1]))
			return res
		
		return res
	
	def update_node_networks(self, node):
		"""
		Get Network defined on node
		"""
		try:
			infos = {}
			
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				netcontroler = self.nlist[node]["netcontroler"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			infos = netcontroler.getConfig()
			
			return infos
		
		except:
			self.logger.log_error("Failed to get %s networks: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot get %s networks: %s" % (node, str(sys.exc_info()[1]))
	
	def update_node_bridges_infos(self, node):
		"""
		Get Network defined on node
		"""
		try:
			infos = {}
			
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				netcontroler = self.nlist[node]["netcontroler"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			infos = netcontroler.updateBridgesInfo()
			event = []
			self.send_event(node, "Networks", "Bridges updated")
			
			return infos
		
		except:
			self.logger.log_error("Failed to update %s bridges infos: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot update %s bridges infos: %s" % (node, str(sys.exc_info()[1]))
	
	
	def get_node_networks(self, node, force):
		"""
		Get Network defined on node
		"""
		try:
			infos = {}
			
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				netcontroler = self.nlist[node]["netcontroler"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			if force == "true":
				infos = netcontroler.getConfig()
			else:
				infos = netcontroler.netconfig
			return infos
		
		except:
			self.logger.log_error("Failed to get %s networks: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot get %s networks: %s" % (node, str(sys.exc_info()[1]))
	
	def create_network(self, node, data):
		"""
		Create a Libvirt network
		"""
		result = ""
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				netcontroler = self.nlist[node]["netcontroler"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
				
			result = netcontroler.create_virtualNetwork(data)
			self.update_node_networks(node)
		
		except:
			self.logger.log_error("Failed to create network s: %s" % str(sys.exc_info()[1]))
			result = "Error: cannot create network: %s" % str(sys.exc_info()[1])
		
		return result
	
	def remove_network(self, node, data):
		"""
		Remove a Libvirt network
		"""
		result = ""
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				netcontroler = self.nlist[node]["netcontroler"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			result = netcontroler.remove_virtualNetwork(data)
			self.update_node_networks(node)
		
		except:
			self.logger.log_warning("Failed to remove network: %s" % str(sys.exc_info()[1]))
			result = "Error: cannot remove: %s" % str(sys.exc_info()[1])
		return result
	
	def update_network(self, node, data):
		"""
		Update Network configuration
		INPUT: node : The KVM node
			   data : JSON data discribing the network configuration
			     Example:
			       { "bridge":"ovsbr1", "name":"vswitch1",
			         "portgroups": [
			           {"is_default":"yes","name":"ALL","vlan_id":"-1","cfg_state":"clean","old_name":"ALL"},
			           {"is_default":"no","name":"VLAN400","vlan_id":"400","cfg_state":"updated","old_name":"VLAN216"}
			         ],
			         "persistent":1,"connections":"2","mode":"bridge","active":1,"type":"openvswitch","old_name":"vswitch1","cfg_state":"clean"
			       }
			
		"""
		result = "Success"
		try:
			# Get up to date Node's network dictionary
			self.update_node_networks(node)
			# Then redefine Libvirt Network
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				netcontroler = self.nlist[node]["netcontroler"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			result = netcontroler.update_virtualNetwork(data)
			
			# Now we have to move VMs that were previously using this Virtual Network
			switch_data = json.loads(data)
			default_pg_name = ""
			for portgroup in switch_data['portgroups']:
				if portgroup['is_default'] == "yes":
					default_pg_name = portgroup['name']
			
			all_vmnic_list = self.list_all_vmnics(node)
			#info['name']  : Virtual machine's name
			#info['vnics'] : List of vnic links for a given VM
				#info['mac']       : Mac Address
				#info['type']      : connection type, either "network" or "bridge"
				#info['vswitch']   : Libvirt Vswitch name
				#info['portgroup'] : Libvirt portgroup (default if empty)
				
			for vm_networks in all_vmnic_list:
				vm_name = vm_networks['name']
				vnic_list = []
				for avnic in vm_networks['vnics']:
					if avnic['vswitch'] == switch_data['old_name']:
						dest_info = {}
						dest_info['mac'] = avnic['mac']
						dest_info['vswitch'] = switch_data['name']
						# search for destination portgroup
						pg_name = default_pg_name
						for portgroup in switch_data['portgroups']:
							if portgroup['old_name'] == avnic['portgroup']:
								pg_name = portgroup['name']
								
						dest_info['portgroup'] = pg_name
						vnic_list.append(dest_info)
				if len(vnic_list) > 0:
					result = self.move_vm_networks(node, vm_name, vnic_list)
			
			# reload Node's network dictionary
			self.update_node_networks(node)
		
		except:
			self.logger.log_warning("Failed to update network: %s" % str(sys.exc_info()[1]))
			return "Error: cannot update network: %s" % str(sys.exc_info()[1])
		
		return result
	
	def move_vm_networks(self, node, vm, network_list):
		"""
		Move a vnic to a new vswtich/portgroup
		PARAMS:
			node             : KVM node
			vm               : Virtual Machine name
			network_list []  : destination networks (List of network dict - see bleow)
				network['mac']       : virtual net mac address (Ref)
				network['vswitch']   : dest Libvirt vswtich
				network['portgroup'] : dest Libvirt portgroup
		
		return Success/Error
		"""
		result = "Success"
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				conn = self.nlist[node]["connection"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			
			domain = conn.lookupByName(vm)
			if domain.isActive():
				vm_active = True
				domain_active_vnic_list = self.get_active_domain_extended_vnics(node, domain)
			else :
				vm_active = False
			
			dom_xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
			dom_dict = xmltodict.parse(dom_xml)
			dom_interface_list = dom_dict['domain']['devices']['interface']
			if isinstance(dom_interface_list, list):
				interface_list = dom_interface_list
			else:
				interface_list = []
				interface_list.append(dom_interface_list)
			
			# Update cold XML definition
			mods = False
			for network in network_list:
				for dom_interface in interface_list:
					if dom_interface['mac']['@address'] == network['mac']:
						if dom_interface['source']['@network'] != network['vswitch']:
							mods = True
							dom_interface['source']['@network'] = network['vswitch']
						
						if network['portgroup']:
							if ( dom_interface['source'].has_key('@portgroup') and
							     dom_interface['source']['@portgroup'] != network['portgroup'] ):
									dom_interface['source']['@portgroup'] = network['portgroup']
									mods = True
							else:
								dom_interface['source']['@portgroup'] = network['portgroup']
								mods = True
						else:
							if dom_interface['source'].has_key('@portgroup'):
								del dom_interface['source']['@portgroup']
								mods = True
						break
			new_dom_xml = xmltodict.unparse(dom_dict, pretty=True)
			if mods:
				conn.defineXML(new_dom_xml)
			# Move vnics if domain is active
			if vm_active:
				for network in network_list:
					for dom_vnic in domain_active_vnic_list['vnics']:
						if dom_vnic['mac'] == network['mac']:
							# We needs to only migrate links that are up
							if dom_vnic['state'] == "up":
								src_dict = {}
								dst_dict = {}
								src_dict['vnic'] = dom_vnic['target']
								src_dict['bridge'] = dom_vnic['source']
								src_dict['state'] = dom_vnic['state']
								dst_dict['type'] = dom_vnic['type']
								dst_dict['vswitch'] = network['vswitch']
								dst_dict['portgroup'] = network['portgroup']
								dst_dict['state'] = src_dict['state']
								result = self.move_vnic_link(node, src_dict, dst_dict)
							break
		except:
			self.logger.log_error("Failed to move %s network: %s" % (vm, str(sys.exc_info()[1])))
			result = "Error: cannot move %s network: %s" % (vm, str(sys.exc_info()[1]))
			
		return result
	
	def move_vnic_link(self, node, source, dest):
		""" call update_vnic_connexion(source,dest) from networklib
		node              : KVM node
		source            : Source Dictionary
		  source['vnic']    : vnic name on KVM server
		  source['bridge']  : Bridge name on KVM server
		  source['state']   : vnic initial state (up/down)
		dest              : Destination Dictionary
		  dest['type']      : Destination type : network or bridge
		  dest['vswitch']   : Libvirt Virtual Network
		  dest['portgroup'] : Libvirt portgroup in Virtual Network
		  dest['state']     : vnic final state (used to simulate plug/unplug of network cables)
		return "Success" / "Error: "
		"""
		
		result = "Success"
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				netcontroler = self.nlist[node]["netcontroler"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			result = netcontroler.update_vnic_connexion(source, dest)
		except:
			self.logger.log_error("Failed to get %s networks: %s" % (node, str(sys.exc_info()[1])))
			result = "Error: cannot get %s networks: %s" % (node, str(sys.exc_info()[1]))
		return result
	
	def get_domain_vnics(self, domain):
		""" Get the list of vnics from the cold configuration of a domain 
		INPUT: a Libvirt Domain pointer
		OUPUT: a list of VM virtual networks dictionaries containing:
			info['mac']       : Mac Address
			info['type']      : connection type, either "network" or "bridge"
			info['vswitch']   : Libvirt Vswitch name
			info['portgroup'] : Libvirt portgroup (default if empty)
		"""
		result = []
		try:
			dom_xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
			dom_dict = xmltodict.parse(dom_xml)
			dom_interface_list = dom_dict['domain']['devices']['interface']
			if isinstance(dom_interface_list, list):
				interface_list = dom_interface_list
			else:
				interface_list = []
				interface_list.append(dom_interface_list)
			
			for dom_interface in interface_list:
				info = {}
				info['mac'] = dom_interface['mac']['@address']
				info['type'] = dom_interface['@type']
				if info['type'] == "network":
					info['vswitch'] = dom_interface['source']['@network']
				elif info['type'] == "bridge":
					info['vswitch'] = dom_interface['source']['@bridge']
				if dom_interface['source'].has_key('@portgroup'):
					info['portgroup'] = dom_interface['source']['@portgroup']
				else:
					info['portgroup'] = ""
				result.append(info)
			
		except:
			self.logger.log_warning("Failed to get domain vnics: %s" % str(sys.exc_info()[1]))
			return [] # return an empty list if a failure occured
		
		return result
	
	def list_all_vmnics(self, node):
		"""
		List all virtual networks for all VMs define in database for KVM node <node>
		OUTPUT: list of dictionaries containing the following:
			info['name']  : Virtual machine's name
			info['vnics'] : List of vnic links for a given VM
			                see get_active_domain_extended_vnics(node, domain) for 
			                the description of the 'vnics' list
		"""
		result = []
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				conn = self.nlist[node]["connection"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			
			allvmlist = self.db.list_vms()
			for vm in allvmlist['vms']:
				if vm['server'] == node:
					vmInfo = {}
					vmInfo['name'] = vm['name']
					vnic_list = []
					try:
						domain = conn.lookupByName(vm['name'])
						vmInfo['vnics'] = self.get_domain_vnics(domain)
						result.append(vmInfo)
						del domain
					except:
						self.logger.log_warning("Domain %s not found on node %s" % (vm['name'], node))
		except:
			self.logger.log_warning("Failed to list VMs networks: %s" % str(sys.exc_info()[1]))
			return "Error: cannot list all VMs networks: %s" % str(sys.exc_info()[1])
		
		return result
	
	def get_active_domain_vnics(self, domain):
		""" Get the list of vnics for an active domain 
		INPUT: a Libvirt Domain pointer
		OUPUT: a list of VM virtual networks dictionaries containing:
			info['mac']       : Mac Address
			info['type']      : connection type, either "network" or "bridge"
			info['vswitch']   : Libvirt Vswitch name
			info['portgroup'] : Libvirt portgroup (default if empty)
			info['target']    : vnic device on the KVM server
			info['state']     : Link state viewed by Libvirt (may differ from real state with OVS)
		"""
		result = []
		try:
			inactive_infos = self.get_domain_vnics(domain)
			if domain.isActive():
				dom_xml = domain.XMLDesc(0)
				dom_dict = xmltodict.parse(dom_xml)
				dom_interface_list = dom_dict['domain']['devices']['interface']
				if isinstance(dom_interface_list, list):
					interface_list = dom_interface_list
				else:
					interface_list = []
					interface_list.append(dom_interface_list)
				
				for dom_interface in interface_list:
					for inactive_nic in inactive_infos:
						# Complete inforamtion with <target> and <state>
						if inactive_nic['mac'] == dom_interface['mac']['@address']:
							info = inactive_nic
							if dom_interface.has_key('target') and dom_interface['target'].has_key('@dev'):
								info['target'] = dom_interface['target']['@dev']
							else:
								info['target'] = "unknown"
							if dom_interface.has_key('link') and dom_interface['link'].has_key('@state'):
								info['state'] = dom_interface['link']['@state']
							else:
								info['state'] = "down"
							
							result.append(info)
							break
			else :
				for inactive_nic in inactive_infos:
					info = inactive_nic
					info['target'] = "unknown"
					info['state'] = "down"
					result.append(info)
				
		except:
			self.logger.log_warning("Failed to get active domain vnics: %s" % str(sys.exc_info()[1]))
			return [] # return an empty list if a failure occured
		
		return result
	
	def get_active_domain_extended_vnics(self, node, domain):
		""" Get the list of vnics for an active domain 
		INPUT: a Libvirt Domain pointer
		OUPUT: a list of VM virtual networks dictionaries containing:
			info['mac']        : Mac Address
			info['type']       : connection type, either "network" or "bridge"
			info['vswitch']    : Libvirt Vswitch name
			info['portgroup']  : Libvirt portgroup (default if empty)
			info['target']     : vnic device on the KVM server
			info['state']      : Real link state (may differ from state viewed by libvirt)
			info['source']     : the name of the OVS or Linux bridge on KVM server
			info['vlan_id']    : the vlan tag
			info['device_type] : "lbr" for a Linux Bridge, "ovs" for an OpenVswtich bridge
		"""
		result = []
		try:
			domain_vnics = self.get_active_domain_vnics(domain)
			if len(domain_vnics) > 0:
				result = self.get_vnics_extended_infos(node, domain_vnics)
		except:
			self.logger.log_warning("Failed to get domain extended vnics infos: %s" % str(sys.exc_info()[1]))
			return [] # return an empty list if a failure occured
		return result
	
	def get_vnics_extended_infos(self, node, vnic_list):
		"""
		Get extended information about VMs' vnics
		call extend_vnic_infos(vnic_list) from networklib
		"""
		result = ""
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				netcontroler = self.nlist[node]["netcontroler"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			
			result = netcontroler.extend_vnic_infos(vnic_list)
		
		except:
			self.logger.log_warning("Failed to get extended information about VMs vnics: %s" % str(sys.exc_info()[1]))
			result = "Error: cannot get extended information about VMs vnics: %s" % str(sys.exc_info()[1])
		return result
	
	def list_active_vmnics(self, node):
		"""
		List all vnic links of active VMs define in database for KVM node <node>
		OUTPUT: list of dictionaries containing the following:
			info['name']  : Virtual machine's name
			info['vnics'] : List of vnic links for a given VM
			                see get_active_domain_extended_vnics(node, domain) for 
			                the description of the 'vnics' list
		"""
		result = []
		try:
			self.nlock.acquire_read()
			if self.nlist.has_key(node):
				conn = self.nlist[node]["connection"]
				self.nlock.release()
			else:
				self.nlock.release()
				return "node not found"
			
			allvmlist = self.db.list_vms()
			active_list = []
			inactive_list = []
			for vm in allvmlist['vms']:
				if vm['server'] == node:
					try:
						domain = conn.lookupByName(vm['name'])
						if domain.isActive():
							active_list.append(vm['name'])
						else:
							inactive_list.append(vm['name'])
						del domain
					except:
						self.logger.log_warning("Domain %s not found on node %s" % (vm['name'], node))
			# First list actives domains
			for vm in active_list:
				domain = conn.lookupByName(vm)
				vmInfo = {}
				vmInfo['name'] = vm
				vmInfo['vnics'] = self.get_active_domain_extended_vnics(node, domain)['vnics']
				result.append(vmInfo)
				del domain
			# Then list inactives domains
			for vm in inactive_list:
				domain = conn.lookupByName(vm)
				vmInfo = {}
				vmInfo['name'] = vm
				vmInfo['vnics'] = self.get_active_domain_extended_vnics(node, domain)['vnics']
				result.append(vmInfo)
				del domain
				
		except:
			self.logger.log_warning("Failed to list active VMs networks: %s" % str(sys.exc_info()[1]))
			return "Error: cannot list VMs networks: %s" % str(sys.exc_info()[1])
		
		return result
	
	def find_vnic_ip(self, node, vm, mac, ip_range):
		""" 
		Try to find a Vnic IP address
		"""
		result = ""
		self.nlock.acquire_read()
		if self.nlist.has_key(node):
			conn = self.nlist[node]["connection"]
			self.nlock.release()
		else:
			self.nlock.release()
			return "node not found"

		try:
			domain = conn.lookupByName(vm)
			vmNics = self.get_active_domain_vnics(domain)
			for vnic in vmNics:
				if vnic['mac'] == mac:
					vnet = vnic['target']
					result = self.nlist[node]["netcontroler"].find_vnet_ip(vnet, mac, ip_range)
					break
		
		except:
			self.logger.log_warning("Failed to find VM ip address: %s" % str(sys.exc_info()[1]))
			return "Error: cannot search IP address: %s" % str(sys.exc_info()[1])
		
		return result

# HANDLE NODE STORAGES AND VDSIK
#
	def create_vdisk(self, vm, node, vdisk, sender, options):
		""" Function to create qemu virtual disk """
		result = "Successful"
		if self.vm_handle.check_locked(vm, node):
			lock = self.vm_handle.get_lock_name(vm, node)
			return "Error: %s is currently locked by a %s process" % (vm, lock)
		try:
			#vdisk = json.loads(data)
			format = vdisk['format']
			alloc = vdisk['allocation']
			size = vdisk['size']
			image = vdisk['image']
			
			cmd = ""
			if format == 'qcow2':
				if alloc == 'preallocation':
					cmd = 'qemu-img create -f '+format+' -o preallocation=metadata '+image+' '+size
				else:
					cmd = 'qemu-img create -f '+format+' '+image+' '+size
			elif format == 'raw':
				if alloc == 'preallocation':
					cmd = "fallocate -l "+size+"G "+image
				else:
					cmd = "truncate --size "+size+"G "+image
			else:
				cmd = "qemu-img create -f "+format+" "+image+" "+size+"G"
			
			res, error = ssh.run(node, cmd)
			if error :
				result = error
			
		except:
			err_msg = str(sys.exc_info()[1])
			self.messenger.log_info("Creating Virtual Disk for %s failed: %s" % (vm, err_msg))
			return "Error: %s " % err_msg
			
		return result
	
	def delete_vdisk(self, vm, node, vdisk, sender, options):
		""" Function to delete qemu virtual disk """
		result = "Successful"
		if self.vm_handle.check_locked(vm, node):
			lock = self.vm_handle.get_lock_name(vm, node)
			return "Error: %s is currently locked by a %s process" % (vm, lock)
		try:
			cmd = "rm -f "+vdisk
			res, error = ssh.run(node, cmd)
			if error :
				result = error
			
		except:
			err_msg = str(sys.exc_info()[1])
			self.messenger.log_info("Deleting Virtual Disk for %s failed: %s" % (vm, err_msg))
			return "Error: %s " % err_msg
			
		return result
	
	def get_vdisk_info(self, vm, node, vdisk, sender, options):
		""" Function to get a virtual disk information """
		result = self.nlist[node]["pools"].getVolumePathConfig(vdisk)
		return result
	
	def erase_vdisk(self, domain, vm, node, vdisk, sender, options):
		""" Function to erase a virtual disk """
		result = "Successful"
		
		if self.vm_handle.check_locked(vm, node):
			lock = self.vm_handle.get_lock_name(vm, node)
			return "Error: %s is currently locked by a %s process" % (vm, lock)
		vmState = self.vm_handle.get_state(domain, vm, node, None)['state']
		if vmState != "shutoff":
			return "Error: %s is not stopped, cannot erase its virtual disk." % vm
		
		try:
			cmd = "virt-format --partition=none -a "+vdisk
			res, error = ssh.run(node, cmd)
			if error :
				result = error
			
		except:
			err_msg = str(sys.exc_info()[1])
			self.messenger.log_info("Erasing Virtual Disk for %s failed: %s" % (vm, err_msg))
			return "Error: %s " % err_msg
			
		return result
	
	
# HANDLE NODES SECURITY
#
	def set_all_nodes_security(self, level):
		res = "done"
		try:
			self.shellinabox_ports = []
			for aNode in self.nlist:
				res = self.set_node_security(aNode, level)
		
		except:
			self.logger.log_warning("Failed to update nodes security: %s" % str(sys.exc_info()[1]))
			return "Error: cannot update nodes security: %s" % str(sys.exc_info()[1])
		
		return res
	
	def set_node_security(self, node, level):
		res = "done"
		self.logger.log_debug("set %s node security to %s" % (node, level))
		try:
			filtered_ip = self.nlist[node]["ip"]
			# Kill all webshell to reconfigure nginx
			if (self.nlist[node].has_key("webshell") and self.nlist[node]["webshell"].has_key("pids")) :
				for pid in self.nlist[node]["webshell"]["pids"]:
					self.logger.log_debug("killing %s" % str(pid))
					os.system("kill -9 %s" % str(pid))
			
			# start shellinabox
			shellinabox = self.check_shellinabox(node)
			self.nlist[node]["webshell"] = shellinabox
			
			# Remove all websockets SSH tunnels 
			ssh_pids = []
			cmd = 'ps fax | grep "ssh -f root@'+node+' " | grep -v "grep" | sed -e "s/ .*//"' 
			res, error = ssh.run(node, cmd)
			ssh_pids = ' '.join(res)
			
			for apid in ssh_pids:
				os.system("kill -9 %s" % apid)
			
			cmd = 'cat /etc/redhat-release | grep "kvm & openkvi"'
			res, error = ssh.run(node, cmd)
			reslines = ' '.join(res)
			if len(reslines) > 0:
				openkvi = True
				# Check if NODE is connected through Nated IP
				if self.nlist[node]["ip"] == "192.168.122.1" :
					cmd = 'grep "MANAGEMENT=" /etc/sysconfig/network-scripts/ifcfg-* | grep "yes" | head -n1 | sed -e "s/.*ifcfg-//" | sed -e "s/:MANAGEMENT.*//"'
					res, error = ssh.run(node, cmd)
					MGNT = ' '.join(res)
					
					if MGNT:
						cmd='ifconfig | grep -A1 "^'+MGNT+'  " | grep inet | sed "s/.*addr://" | sed "s/ .*//"'
						res, error = ssh.run(node, cmd)
						tmp_ip = ' '.join(res)
						
						if re.match( "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" , tmp_ip) :
							filtered_ip = tmp_ip
				
			else:
				openkvi = False
			
			
			# Clear all rules before any things
			cmd = 'iptables -t filter -D INPUT -d '+filtered_ip+' -j DROP'
			res, error = ssh.run(node, cmd)
			
			cmd = 'iptables -t filter -D INPUT -d '+filtered_ip+' -p tcp --dport 22 -j ACCEPT'
			res, error = ssh.run(node, cmd)
			
			cmd = 'iptables -t filter -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT'
			res, error = ssh.run(node, cmd)
			
			#VNC access 
			#cmd = 'iptables -D INPUT -d '+filtered_ip+' -p tcp --dport 5900:6900 -j ACCEPT'
			#proc = subprocess.Popen(['ssh','-x','root@'+node, cmd], stdout=subprocess.PIPE)
			#retcode = proc.wait()
			
			if openkvi:
				cmd = 'iptables -t filter -D INPUT -d '+filtered_ip+' -p tcp --dport 443 -j ACCEPT'
				res, error = ssh.run(node, cmd)
				cmd = 'iptables -t filter -D INPUT -d '+filtered_ip+' -p tcp --dport 80 -j ACCEPT'
				res, error = ssh.run(node, cmd)
			
			if level == "high":
				cmd = 'iptables -A INPUT -d '+filtered_ip+' -p tcp --dport 22 -j ACCEPT'
				res, error = ssh.run(node, cmd)
				# VNC access 
				#cmd = 'iptables -A INPUT -d '+filtered_ip+' -p tcp --dport 5900:6900 -j ACCEPT'
				#proc = subprocess.Popen(['ssh','-x','root@'+node, cmd], stdout=subprocess.PIPE)
				#retcode = proc.wait()
				
				if openkvi:
					cmd = 'iptables -A INPUT -d '+filtered_ip+' -p tcp --dport 443 -j ACCEPT'
					res, error = ssh.run(node, cmd)
					cmd = 'iptables -A INPUT -d '+filtered_ip+' -p tcp --dport 80 -j ACCEPT'
					res, error = ssh.run(node, cmd)
					
				cmd = 'iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT'
				res, error = ssh.run(node, cmd)
				
				cmd = 'iptables -A INPUT -d '+filtered_ip+' -j DROP'
				res, error = ssh.run(node, cmd)
				
			cmd = 'rm -f /etc/sysconfig/iptables; /sbin/service iptables save'
			res, error = ssh.run(node, cmd)
			
		except:
			self.logger.log_warning("Failed to update node %s security: %s" % (node, str(sys.exc_info()[1])))
			return "Error: cannot update node %s security: %s" % (node, str(sys.exc_info()[1]))
		
		return res
	
