#!/usr/bin/python -u
"""
Library to control Virtual Machines with libvirt
"""

import os
import subprocess
import time
import libvirt
import threading
from rwlock import RWLock
import sys
import socket
from xml.dom.minidom import parseString, Element
import re
import json
import virterrors
import ssh

def str_to_bool(s):
	if s == 'True':
		return True
	else :
		return False


class VMSControler:
	def __init__(self, messenger, database):
		"""
		Init Controler class
		"""
		self.messenger = messenger
		#self.lockedList = []
		self.vmInfos = {}
		self.global_lock = RWLock()
		self.freeport_lock = RWLock()
		self.tasks_lock = RWLock()
		self.db = database
		self.pending_tasks = {}
	
	def init_vm(self, vm, node, domain):
		self.init_vm_infos(vm, node)
		self.vmInfos[node][vm]["websockets"] = []
		if not self.pending_tasks.has_key(vm):
			self.pending_tasks[vm] = []
	
	def write_file(self, infile, content):
		""" Common write function """
		(path,afile) = os.path.split(infile)
		os.system('mkdir -p '+path)
		f = open(infile, 'w')
		f.write(content)
		f.close()
		dirname = os.path.dirname(infile)
		user = os.stat(dirname).st_uid
		group = os.stat(dirname).st_gid
		os.chown(infile, user, group)

	def make_dir(self, path):
		""" Common mkdir function """
		os.makedirs(path)
		dirname = os.path.dirname(path)
		user = os.stat(dirname).st_uid
		group = os.stat(dirname).st_gid
		os.chown(path, user, group)

	def init_vm_infos(self, vm, node):
		self.global_lock.acquire_write()
		info = {}
		info["locked"] = False
		info["lockName"] = ""
		info["state"] = ""
		if not self.vmInfos.has_key(node):
			self.vmInfos[node] = {}
		if not self.vmInfos[node].has_key(vm):
			self.vmInfos[node][vm] = info
		self.global_lock.release()

	def check_locked(self, vm, node):
		""" Check if VM has been locked """
		try:
			vmlocked = False
			type = ""
			self.global_lock.acquire_read()
			if self.vmInfos.has_key(node) and self.vmInfos[node].has_key(vm):
				vmlocked = self.vmInfos[node][vm]["locked"]
				self.global_lock.release()
			else:
				self.global_lock.release()
				self.init_vm_infos(vm, node)
		except:
			self.messenger.log_debug("error in check_locked: %s" % str(sys.exc_info()[1]))
		
		return vmlocked
	
	def get_lock_name(self, vm, node):
		""" Check if VM has been locked """
		try:
			vmlocked = False
			type = ""
			self.global_lock.acquire_read()
			if self.vmInfos.has_key(node) and self.vmInfos[node].has_key(vm):
				vmlock = self.vmInfos[node][vm]["lockName"]
				self.global_lock.release()
			else:
				self.global_lock.release()
				self.init_vm_infos(vm, node)
		except:
			self.messenger.log_debug("error in get_lock_name: %s" % str(sys.exc_info()[1]))
		
		return vmlock
	
	def acquire_lock(self, vm, node, detail, sender):
		""" Add VM to the locked list """
		vmlocked = False
		self.global_lock.acquire_read()
		if self.vmInfos.has_key(node) and self.vmInfos[node].has_key(vm):
			vmlocked = self.vmInfos[node][vm]["locked"]
			lockName = self.vmInfos[node][vm]["lockName"]
			self.global_lock.release()
		else:
			self.global_lock.release()
			self.init_vm_infos(vm, node)
		
		if vmlocked == False:
			self.global_lock.acquire_write()
			#self.lockedList.append(vm)
			self.vmInfos[node][vm]["locked"] = True
			self.vmInfos[node][vm]["lockName"] = detail
			self.global_lock.release()
			log = {}
			log["vm"] = vm
			log["node"] = node
			log["task"] = "lock"
			log["event"] = "VM_INFO"
			log["status"] = "Locked"
			log["detail"] = detail
			log["sender"] = sender
			self.messenger.tell_all("EVENT", log)
	
	def release_lock(self, vm, node, detail, sender):
		""" remove VM from the locked list """
		vmlocked = False
		self.global_lock.acquire_read()
		if self.vmInfos.has_key(node) and self.vmInfos[node].has_key(vm):
			vmlocked = self.vmInfos[node][vm]["locked"]
			lockName = self.vmInfos[node][vm]["lockName"]
			self.global_lock.release()
		else:
			self.global_lock.release()
			self.init_vm_infos(vm, node)
		
		if vmlocked == True:
			self.global_lock.acquire_write()
			self.vmInfos[node][vm]["locked"] = False
			#self.vmInfos[vm]["lockName"] = detail
			#self.lockedList.remove(vm)
			self.global_lock.release()
			log = {}
			log["vm"] = vm
			log["node"] = node
			log["task"] = "lock"
			log["event"] = "VM_INFO"
			log["status"] = "Unlocked"
			log["detail"] = detail
			log["sender"] = sender
			self.messenger.tell_all("EVENT", log)
		

	def info(self, dom):
		""" Translate vm state """ 
		states = {
			libvirt.VIR_DOMAIN_NOSTATE: 'no state',
			libvirt.VIR_DOMAIN_RUNNING: 'running',
			libvirt.VIR_DOMAIN_BLOCKED: 'blocked',
			libvirt.VIR_DOMAIN_PAUSED: 'paused',
			libvirt.VIR_DOMAIN_SHUTDOWN: 'being shut down',
			libvirt.VIR_DOMAIN_SHUTOFF: 'shutoff',
			libvirt.VIR_DOMAIN_CRASHED: 'crashed',
			}
		try:
			[state, maxmem, mem, ncpu, cputime] = dom.info()
			strState = states.get(state, state)
		except: 
			strState = 'no state'
			maxmem = 0
			mem = 0
			ncpu = 0
			cputime = 0
		
		return [strState, maxmem, mem, ncpu, cputime]

	def add_etchosts(self, node, ip, lines):
		""" Add name and ip of node to remote /etc/hosts """
		toadd = True
		modified = False
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
					modified = True
		if toadd :
			lines.append(ip+"    "+node+"\n")
			modified = True
		
		result = ""
		for aline in lines:
			result += aline 
		return result, modified
	
	def get_task_infos(self, task):
		sender = "Node Manager"
		sendMsg = True
		self.tasks_lock.acquire_read()
		found_task = {}
		try:
			vm = task['vm']
			for pendingTask in self.pending_tasks[vm]:
				if ( pendingTask['task'] == task["task"] and
				     pendingTask['node'] == task["node"] and
				     pendingTask['status'] == task["status"] ):
					found_task = pendingTask
		except:
			self.messenger.log_debug("error in get_task_infos %s" % str(sys.exc_info()[1]))
			
		self.tasks_lock.release()
		return found_task
	
	def remove_pending_tasks(self, task):
		self.tasks_lock.acquire_write()
		try:
			vm = task['vm']
			to_remove = []
			for pendingTask in self.pending_tasks[vm]:
				if ( pendingTask['task'] == task["task"] 
					and pendingTask['node'] == task["node"] 
					and pendingTask['sender'] == task["sender"] 
					and pendingTask['status'] == task["status"] ):
					to_remove.append(pendingTask)
			for task2del in to_remove:
				self.pending_tasks[vm].remove(task2del)
		except:
			self.messenger.log_debug("error in remove_pending_tasks %s" % str(sys.exc_info()[1]))
		
		self.tasks_lock.release()
	
	def add_pending_tasks(self, task, expire=None):
		self.tasks_lock.acquire_write()
		if not task.has_key('send_msg'):
			task['send_msg'] = True
		newtask = task.copy()
		
		if not expire:
			expire = 30
		try:
			vm = task['vm']
			self.pending_tasks[vm].append(newtask)
		except:
			self.messenger.log_debug("error in add_pending_tasks %s" % str(sys.exc_info()[1]))
		
		self.tasks_lock.release()
		# Force task removing after a certain amount of time (seconds)
		t = threading.Timer(expire, self.remove_pending_tasks, (newtask,))
		t.start()
	
	
	def send(self, domain, action, vm, node, sender, options=[]):
		""" Send commands to control a VM state """
		result = ""
		progress = "False"
		if self.check_locked(vm, node):
			lock = self.get_lock_name(vm, node)
			return "Error: %s is currently locked by a %s process" % (vm, lock)
		for option in options:
			if "progress" in option:
				args = option.split('=')
				progress = args[1].strip()
				self.messenger.log_debug("need to monitor progress for %s: %s" % (vm, progress))
		try:
			result = self.libvirt_exec(domain, action, vm, node, sender, str_to_bool(progress))
		except:
			self.messenger.log_error("Sending %s to %s has failed: %s" % (action, vm, sys.exc_info()[1]))
		return result
	
	def libvirt_exec(self, domain, action, vm, node, sender, progress=False):
		log = {}
		log["node"] = node
		log["vm"] = vm
		log["task"] = action
		log["sender"] = sender
		task = log.copy()
		task['status'] = ""
		try:
			vmState = self.get_state(domain, vm, node, None)['state']
			if (action == "start"):
				if not domain.isActive():
					if vmState == "paused":
						task['task'] = "Resumed"
						task['status'] = "Unpaused"
					elif vmState == "suspended":
						task['task'] = "Started"
						task['status'] = "Restored"
						if progress:
							log["task"] = "Started"
							self.start_job_progress_thread(domain, vm, node, log)
					else:
						task['task'] = "Started"
						task['status'] = "Booted"
					
					self.messenger.log_debug("start "+vm)
					self.add_pending_tasks(task)
					domain.create()
					result = "command sent"
				else: 
					result = "Warning, %s already active" % vm
			
			elif (action == "shutdown"):
				if domain.isActive():
					task['task'] = "Stopped"
					task['status'] = "Shutdown"
					self.add_pending_tasks(task, 120)
					domain.shutdown()
					result = "command sent"
				else: 
					result = "Warning, %s already shutoff" % vm
			
			elif (action == "kill"):
				if vmState != "shutoff":
					task['task'] = "Stopped"
					task['status'] = "Destroyed"
					self.add_pending_tasks(task)
					domain.destroy()
					result = "command sent"
					#self.stop_websocket(vm, node)
				else: 
					result = "Warning, %s already in shutoff" % vm
			
			elif (action == "reboot"):
				if domain.isActive():
					task['task'] = "Shutdown"
					task['status'] = "Finished"
					self.add_pending_tasks(task,300)
					domain.reboot(0)
					result = "command sent"
				else: 
					result = "Warning, %s already shutdown" % vm
			
			elif (action == "suspend"):
				if domain.isActive():
					if progress:
						log["task"] = "Suspend"
						self.messenger.log_debug("following progress of "+vm)
						self.start_job_progress_thread(domain, vm, node, log)
					
					task['task'] = "Suspended"
					task['status'] = "Paused"
					task['send_msg'] = False
					self.add_pending_tasks(task,300)
					
					task['task'] = "Stopped"
					task['status'] = "Saved"
					task['send_msg'] = True
					self.add_pending_tasks(task,300)
					flags = 0
					domain.managedSave(flags)
					result = "command sent"
				else: 
					result = "Warning, %s is not running" % vm
			
			elif (action == "pause"):
				if domain.isActive():
					if progress:
						self.messenger.log_debug("following progress of "+vm)
						self.start_job_progress_thread(domain, vm, node, log)
					
					task['task'] = "Suspended"
					task['status'] = "Paused"
					self.add_pending_tasks(task, 60)
					domain.suspend()
					result = "command sent"
				else: 
					result = "Warning, %s is not running" % vm
			
			elif (action == "resume"):
				if vmState == 'paused':
					task['task'] = "Resumed"
					task['status'] = "Unpaused"
					self.add_pending_tasks(task,120)
					domain.resume()
					result = "command sent"
				else: 
					result = "Warning, %s already in state %s" % (vm, vmState)
		
		except:
			result = str(sys.exc_info()[1])
			self.messenger.log_error("%s %s failed: %s" % (action, vm, result))
		
		return result
	
	def libvirt_define(self, conn, vm, xml, node, sender):
		""" Create a VM  from xml without starting it """
		result = "Successful"
		try:
			task = {}
			task['task'] = 'Defined'
			task['vm'] = vm
			task['node'] = node
			task['sender'] = sender
			task['status'] = 'Added'
			self.add_pending_tasks(task)
			conn.defineXML(xml)
		except:
			self.messenger.log_error("Call to Libvirt Define for %s has failed: %s" % (vm, str(sys.exc_info()[1])))
			self.messenger.log_debug("virtual machine xml:"+xml)
			return "Error: cannot define %s: %s" % (vm, str(sys.exc_info()[1]))
		
		return result
	
	def define(self, conn, vm, xml, node, sender):
		""" Create a VM  from xml without starting it """
		result = "Successful"
		if self.check_locked(vm, node):
			lock = self.get_lock_name(vm, node)
			return "Error: %s is currently locked by a %s process" % (vm, lock)
		try:
			if self.pending_tasks.has_key(vm):
				self.tasks_lock.acquire_read()
				for pendingTask in self.pending_tasks[vm]:
					if pendingTask["task"] == "Migration":
						destnode = pendingTask["status"]
						srcnode = pendingTask["node"]
						if node in destnode or node in srcnode:
							return "Error: a VM with name %s is currently been migrated from %s to %s" % (vm, srcnode, destnode)
				self.tasks_lock.release()
			else:
				self.pending_tasks[vm] = []
			
			result = self.libvirt_define(conn, vm, xml, node, sender)
		except:
			self.messenger.log_error("Defining %s failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot define %s: %s" % (vm, str(sys.exc_info()[1]))
		
		return result
	
	def add(self, vm, node, domain, sender):
		""" Add a VM in inventory """
		result = "Successful"
		log = {}
		log['task'] = 'Add'
		log['vm'] = vm
		log['node'] = node
		log['sender'] = sender
		log["event"] = "VM_INFO"
		log["status"] = result
		try:
			self.messenger.log_info("Adding virtual machine "+vm)
			xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
			infos = self.extract_xml_info(xml)
			infos["server"] = node
			diskList = infos['disks']
			disks = ""
			for aDisk in diskList:
				sourceAttr = aDisk.split("/")
				if (len(sourceAttr) > 0):
					file = sourceAttr[-1]
				else:
					file = ""
				if disks == "":
					disks = file
				else:
					disks += ", "+file[0]
				
			infos['disks'] = disks
			
			res = self.db.add_vm(infos)
			if "Failed" not in res:
				self.init_vm(vm, node, "")
			else:
				err = res.split("::")
				result = "Error: cannot insert data :"+err[1]
				log["status"] = result
		except:
			self.messenger.log_warning("Adding %s to DB has failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot add %s to database: %s" % (vm, str(sys.exc_info()[1]))
		
		self.messenger.tell_all("EVENT", log)
		return result
	
	def libvirt_undefine(self, domain, vm, node, sender):
		""" Remove a VM from libvirt inventory """
		diskList = []
		result = ""
		try:
			self.stop_websocket(vm, node)
			vmState = self.get_state(domain, vm, node, None)['state']
			if vmState != "shutoff":
				if self.vmInfos[node][vm].has_key("websockets") and len(self.vmInfos[node][vm]["websockets"]) > 0:
					self.stop_websocket(vm, node)
				try:
					domain.destroy()
				except:
					self.messenger.log_warning("Cannot stop %s! It may still be running on %s" % (vm, node))
			xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
			infos = self.extract_xml_info(xml)
			diskList = infos['disks']
			task = {}
			task['task'] = 'Undefined'
			task['vm'] = vm
			task['node'] = node
			task['sender'] = sender
			task['status'] = 'Removed'
			task["send_msg"] = False
			self.add_pending_tasks(task)
			undef_flags = libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE
			undef_flags |= libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA
			res = domain.undefineFlags(undef_flags)
			result = virterrors.ERROR[res]
			for aDisk in diskList:
				## remove remote dirs
				self.messenger.log_info("Deleting %s from %s" % (aDisk.strip(), node))
				cmd = "rm -f "+aDisk.strip()+" 2>/dev/null"
				subprocess.call(['ssh','-x','root@'+node, cmd])
			log = {}
			log['task'] = 'Delete'
			log['vm'] = vm
			log['node'] = node
			log['sender'] = sender
			log['event'] = "VM_INFO"
			log['status'] = result
			self.messenger.tell_all("EVENT", log)
			
		except:
			self.messenger.log_warning("Call to Libvirt Undefine for %s has failed: %s" % (vm, str(sys.exc_info()[1])))
			result = "Error: cannot undefine %s: %s" % (vm, str(sys.exc_info()[1]))
		
		return result
	
	def undefine(self, domain, vm, node, sender):
		""" Remove a VM from libvirt inventory """
		result = ""
		if self.check_locked(vm, node):
			lock = self.get_lock_name(vm, node)
			return "Error: %s is currently locked by a %s process" % (vm, lock)
		try:
			result = self.libvirt_undefine(domain, vm, node, sender)
		except:
			self.messenger.log_warning("Undefining %s failed: %s" % (vm, str(sys.exc_info()[1])))
			result = "Error: cannot undefine %s: %s" % (vm, str(sys.exc_info()[1]))
		return result
	
	def remove(self, vm, node, sender, options):
		""" Remove a VM from database inventory """
		result = "Successful"
		log = {}
		log['task'] = 'Remove'
		log['vm'] = vm
		log['node'] = node
		log['sender'] = sender
		log["event"] = "VM_INFO"
		log["status"] = result
		try:
			self.messenger.log_info("Removing virtual machine "+vm)
			self.db.remove_vm(vm, node)
		except:
			self.messenger.log_warning("removing %s from DB has failed: %s" % (vm, str(sys.exc_info()[1])))
			result = "Error: cannot remove %s from database: %s" % (vm, str(sys.exc_info()[1]))
			log["status"] = result
		
		self.messenger.tell_all("EVENT", log)
		return result
	
	def virtop(self, vm, node):
		""" Run virtop for a VM"""
		result = ""
		cmd = 'virt-top --stream -n 2 | grep " %s$" | sed -e "s/ /;/g" | sed -e "s/;;*/;/g" | tail -n1' % vm
		res, error = ssh.run(node, cmd)
		if error :
			result = error
		else:
			result = ' '.join(res)
		return result
	
	def update_nginx(self, port):
		try:
			restart_nginx = False
			## Configure NGINX SSL proxy
			f = open('/etc/nginx/conf.d/openkvi_nginx_ssl.conf', 'r')
			ssl_lines = f.readlines()
			f.close()
			to_add = True
			ref_line = "location /ws/"+port+" {"
			for aline in ssl_lines:
				if ref_line in aline:
					to_add = False
					break
			
			if to_add:
				for i in range(len(ssl_lines)-1, -1, -1):
					if "}" in ssl_lines[i]:
						ssl_lines.pop(i)
						break
				
				ssl_lines.append("    location /ws/"+port+" {\n")
				if self.messenger.security != "low":
					ssl_lines.append("        access_by_lua_file /etc/nginx/conf.d/authenticate.lua;\n")
				ssl_lines.append("        proxy_pass http://127.0.0.1:"+port+";\n")
				ssl_lines.append("        proxy_http_version 1.1;\n")
				ssl_lines.append("        proxy_set_header Upgrade $http_upgrade;\n")
				ssl_lines.append("        proxy_set_header Connection $connection_upgrade;\n")
				ssl_lines.append("    }\n")
				ssl_lines.append("}\n")
				
				f = open('/etc/nginx/conf.d/openkvi_nginx_ssl.conf', 'w')
				f.writelines(ssl_lines)
				f.close()
				restart_nginx = True
				
			## Configure NGINX  proxy
			f = open('/etc/nginx/conf.d/openkvi_nginx_default.conf', 'r')
			http_lines = f.readlines()
			f.close()
			to_add = True
			ref_line = "location /ws/"+port+" {"
			for aline in http_lines:
				if ref_line in aline:
					to_add = False
					break
			
			if to_add:
				for i in range(len(http_lines)-1, -1, -1):
					if "}" in http_lines[i]:
						http_lines.pop(i)
						break
			if to_add:
				http_lines.append("    location /ws/"+port+" {\n")
				http_lines.append("        proxy_pass http://127.0.0.1:"+port+";\n")
				http_lines.append("        proxy_http_version 1.1;\n")
				http_lines.append("        proxy_set_header Upgrade $http_upgrade;\n")
				http_lines.append("        proxy_set_header Connection $connection_upgrade;\n")
				http_lines.append("    }\n")
				http_lines.append("}\n")
				
				f = open('/etc/nginx/conf.d/openkvi_nginx_default.conf', 'w')
				f.writelines(http_lines)
				f.close()
				restart_nginx = True
				
			if restart_nginx:
				os.system("service nginx reload")
			
		except:
			self.messenger.log_error("Failed to update nginx configuration: %s" % str(sys.exc_info()[1]))
		
	
	def stop_websocket(self, vm, node):
		try:
			if self.vmInfos[node][vm].has_key("websockets"):
				for websock in self.vmInfos[node][vm]["websockets"]:
					pid = websock['pid']
					self.messenger.log_debug("sending signal.SIGKILL to "+pid)
					os.system("kill -9 "+pid)
			self.vmInfos[node][vm]["websockets"] = []
		except:
			self.messenger.log_error("Failed to stop websocket for domain %s: %s" % (vm, str(sys.exc_info()[1])))
	
	def start_websocket(self, vm, node, domain, offset = 0):
		""" Start a websocket for remote VNC access with noVNC """
		self.messenger.log_debug("Starting Websocket for "+vm)
		result = "-1"
		try:
			ip = socket.gethostbyname(node)
			xml_active = domain.XMLDesc(0)
			xmlActiveDom = parseString(xml_active)
			displayNodes = xmlActiveDom.getElementsByTagName("graphics")
			websockets = []
			for display in displayNodes:
				port  = display.getAttribute('port')
				if self.messenger.security != "low":
					newport = offset+(int(port)-5900)
					cmd = "ssh -f root@"+node+" -N -L "+str(newport)+":127.0.0.1:"+port
					#proc = subprocess.Popen(['ssh', cmd], stdout=subprocess.PIPE)
					#code = proc.wait()
					os.system(cmd)
					port = str(newport)
					ip = "127.0.0.1"
				
				proc = subprocess.Popen(['sh','/usr/share/tomcat/webapps/openkvi/resources/novnc/launch_socket.sh',ip+':'+port], stdout=subprocess.PIPE)
				code = proc.wait()
				for aline in proc.stdout:
					#"PID=$PYPID;PORT=$i;TARGET=$TARGET"
					if "PID=" in aline:
						infos = aline.split(';')
						pid = infos[0].split('=')[1].strip()
						local_port = infos[1].split('=')[1].strip()
						websock = {}
						websock['port'] = local_port
						websock['pid'] = pid
						websockets.append(websock)
						self.messenger.log_debug('run websockify on '+local_port+' to reach '+ip+':'+port)
						self.update_nginx(local_port)
			
			self.vmInfos[node][vm]["websockets"] = websockets
			
		except:
			self.messenger.log_error("Failed to start websocket for domain %s: %s" % (vm, str(sys.exc_info()[1])))
			return result
		
		return result
	
	def get_websocket(self, vm, domain, node, offset):
		""" Get the list of opened websockets """
		result = "-1"
		self.messenger.log_debug("Getting virtual machine %s display" % vm)
		try:
			if domain.isActive():
				if not self.vmInfos[node][vm].has_key("websockets"):
					self.start_websocket(vm, node, domain, offset)
				elif len(self.vmInfos[node][vm]["websockets"]) == 0:
					self.start_websocket(vm, node, domain, offset)
					
				for asock in self.vmInfos[node][vm]["websockets"]:
					self.messenger.log_debug("%s Websocket: [%s, %s] " % (vm, asock['pid'], asock['port']))
					if result == "-1":
						result = asock['port']
					else:
						result = "," + asock['port']
		except:
			self.messenger.log_error("Failed to get websocket port for domain %s: %s" % (vm, str(sys.exc_info()[1])))
		
		return result
	
	def clearAllWebsockets(self, node):
		for aVm in self.vmInfos[node].keys():
			if self.vmInfos[node][aVm].has_key("websockets"):
				for websock in self.vmInfos[node][aVm]["websockets"]:
					pid = websock['pid']
					os.system("kill -9 "+pid)
			
			self.vmInfos[node][aVm]["websockets"] = []
	
	def getXmlText(self, element):
		rc = []
		for node in element.childNodes:
			if node.nodeType == node.TEXT_NODE:
				rc.append(node.data)
		return ''.join(rc)
	
	def extract_xml_info(self, xml):
		infos = {}
		try:
			xmlDom = parseString(xml)
			
			#file = source.getAttribute('file')
			nameNode = xmlDom.getElementsByTagName("name")[0]
			infos["name"] = self.getXmlText(nameNode)
			infos["displayedname"] = infos["name"] 
			
			memNode = xmlDom.getElementsByTagName("memory")[0]
			infos["memory"] = int(self.getXmlText(memNode))
			cpuNode = xmlDom.getElementsByTagName("vcpu")[0]
			infos["nbcpu"] = int(self.getXmlText(cpuNode))
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
			disks = []
			for diskNode in diskNodes:
				type = diskNode.getAttribute('type')
				device = diskNode.getAttribute('device')
				if type == "file" and device == "disk" :
					sourceEl = diskNode.getElementsByTagName("source")
					if len(sourceEl) > 0:
						source = sourceEl[0]
						fileAtr = source.getAttribute('file')
						disks.append(fileAtr)
			
			infos['disks'] = disks
			
		except:
			self.messenger.log_warning("extract XML infos failed: %s" % str(sys.exc_info()[1]))
			return "Error: cannot extract XML infos: %s" % str(sys.exc_info()[1])
		
		return infos
	
	def get_active_vnics(self, domain):
		result  = {}
		result['vnics'] = {}
		result['error'] = ""
		try:
			xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
			active_info = {}
			if domain.isActive():
				xml_active = domain.XMLDesc(0)
				xmlActiveDom = parseString(xml_active)
				activeNetNodes = xmlActiveDom.getElementsByTagName("interface")
				for activeNetNode in activeNetNodes:
					if len(activeNetNode.getElementsByTagName("target")) > 0:
						elActTarget = activeNetNode.getElementsByTagName("target")[0]
						vnic = elActTarget.getAttribute('dev')
						elActMac = activeNetNode.getElementsByTagName("mac")[0]
						actMac = elActMac.getAttribute('address').strip()
						active_info[actMac] = {}
						active_info[actMac]['target'] = vnic
			
			vnic_list = self.parse_network_xml(xml)
			for aVnic in vnic_list:
				mac = aVnic['mac']
				if active_info.has_key(mac):
					aVnic['target'] = active_info[mac]['target']
				else:
					aVnic['target'] = ''
				del aVnic['mac']
				
				result['vnics'][mac] = aVnic
			
		except:
			self.messenger.log_warning("VNets states: extract XML infos failed: %s" % str(sys.exc_info()[1]))
			result['error'] = "Error: cannot get Virtual Networks states: %s" % str(sys.exc_info()[1])
			
		return result
	
	def is_network_device(self, xml):
		result = False
		try:
			xmlDom = parseString(xml)
			netNodes = xmlDom.getElementsByTagName("interface")
			if len(netNodes) > 0:
				result = True
		except:
			result = False
			
		return result
	
	def parse_network_xml(self, xml):
		result = []
		try:
			xmlDom = parseString(xml)
			netNodes = xmlDom.getElementsByTagName("interface")
			for netNode in netNodes:
				net_infos = {}
				elMac = netNode.getElementsByTagName("mac")[0]
				mac = elMac.getAttribute('address').strip()
				net_infos['mac'] = mac
				elLinks = netNode.getElementsByTagName("link")
				if len(elLinks) > 0:
					state = elLinks[0].getAttribute('state').strip()
				else:
					state = "unknown"
				net_infos['state'] = state
				
				portgroup = ""
				type = netNode.getAttribute('type')
				if type == "bridge" :
					source = netNode.getElementsByTagName("source")[0]
					device = source.getAttribute('bridge').strip()
				elif type == "network":
					source = netNode.getElementsByTagName("source")[0]
					device = source.getAttribute('network').strip()
					if source.hasAttribute('portgroup'):
						portgroup = source.getAttribute('portgroup').strip()
				
				net_infos['type'] = type
				net_infos['device'] = device
				net_infos['portgroup'] = portgroup
				
				result.append(net_infos)
			
		except:
			self.messenger.log_warning("Cannot parse network XML: %s" % str(sys.exc_info()[1]))
			
		return result
	
	def live_update_device(self, domain, vm, node, xml, sender, options):
		""" Special function to update CDROM and HD configuration """
		result = "Successful"
		if self.check_locked(vm, node):
			lock = self.get_lock_name(vm, node)
			return "Error: %s is currently locked by a %s process" % (vm, lock)
		
		try:
			if domain.isActive():
				result = domain.updateDeviceFlags(xml, libvirt.VIR_DOMAIN_AFFECT_LIVE)
			else:
				result = "Warning cannot do live update on an inactive domain"
			
		except:
			err_msg = str(sys.exc_info()[1]).replace("this function is not supported by the connection driver: ", "")
			self.messenger.log_info("Updating %s failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: %s " % err_msg
			
		if result == 0:
			result = "Successful"
			
		return result
	
	def update_conf(self, conn, vm, xml, node, sender, device):
		""" Function to update XML info"""
		result = "Successful"
		if self.check_locked(vm, node):
			lock = self.get_lock_name(vm, node)
			return "Error: %s is currently locked by a %s process" % (vm, lock)
		
		try:
			task = {}
			task['task'] = 'Defined'
			task['vm'] = vm
			task['node'] = node
			task['sender'] = sender
			task['status'] = 'Updated'
			if device == "networks":
				task['show_task'] = 'Update Virtual Machine NICs'
			elif device == "processor":
				task['show_task'] = 'Update Virtual Machine CPUs'
			elif device == "memory":
				task['show_task'] = 'Update Virtual Machine Memory'
			elif device == "bios":
				task['show_task'] = 'Update Virtual Machine Bios'
			elif device == "storages":
				task['show_task'] = 'Update Virtual Machine Storages'
			elif device == "video":
				task['show_task'] = 'Update Virtual Machine Video'
			elif device == "input":
				task['show_task'] = 'Update Virtual Machine Input'
			
			self.add_pending_tasks(task,20)
			conn.defineXML(xml) 
			
		except:
			self.messenger.log_warning("Updating %s failed: %s" % (vm, str(sys.exc_info()[1])))
			result = "Error: cannot update %s: %s" % (vm, str(sys.exc_info()[1]))
		
		return result
	
	def vm_updated(self, log):
		try:
			pending_task = self.get_task_infos(log)
			for aKey in log.keys():
				if not pending_task.has_key(aKey):
					pending_task[aKey] = log[aKey]
			
			self.messenger.tell_all("EVENT", pending_task)
			self.remove_pending_tasks(pending_task)
		except:
			self.messenger.log_warning("Updating %s failed: %s" % (vm, str(sys.exc_info()[1])))
	
	def get(self, domain, request, vm, node, options):
		result = "Error: Unknown request"
		if request == "xml":
			result = self.get_xml(domain, vm, options)
		if request == "state":
			result = self.get_state(domain, vm, node, options)
		if request == "interfaces":
			result = self.get_interfaces(domain, vm)
		if request == "jobinfo":
			result = self.get_jobinfo(domain, vm)
		
		return result
	
	def get_state(self, domain, vm, node, options=None):
		self.messenger.log_debug("trying to get state of "+vm)
		strState = ""
		
		infos = {}
		if self.vmInfos[node].has_key(vm):
			[strState, maxmem, mem, ncpu, cputime] = self.info(domain)
			if strState == "shutoff":
				if domain.hasManagedSaveImage(0):
					strState = "suspended"
				# Stop zombies websockets
				if self.vmInfos[node][vm].has_key("websockets") and len(self.vmInfos[node][vm]["websockets"]) > 0:
					self.stop_websocket(vm, node)
			
			not_initialized = False
			self.global_lock.acquire_read()
			if not self.vmInfos.has_key(node) and not self.vmInfos[node].has_key(vm):
				not_initialized = True
			self.global_lock.release()
			if not_initialized:
				self.init_vm_infos(vm, node)
				
			self.global_lock.acquire_write()
			self.vmInfos[node][vm]["state"] = strState
			infos = self.vmInfos[node][vm]
			self.global_lock.release()
			
			self.messenger.log_debug("Got state of "+vm+" -> "+strState)
		else:
			infos['state'] = "Error vm %s has not been found on %s" % (vm,node)
			
		return infos
	
	def get_xml(self, domain, vm, options):
		self.messenger.log_debug("trying to get xml of "+vm)
		path = "/tmp/"+vm+".xml"
		for option in options: 
			if "path" in option:
				args = option.split('=')
				path = args[1].strip()
				
		try:
			xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
			xml_active = domain.XMLDesc(0)
			dir_path = os.path.dirname(path)
			if not os.path.exists(dir_path):
				#os.mkdir(dir_path)
				self.make_dir(dir_path)
			self.write_file(path, xml)
			self.write_file(path+"-active", xml_active)
		except:
			self.messenger.log_warning("get XML of %s failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot get XML of %s: %s" % (vm, str(sys.exc_info()[1]))
		
		self.messenger.log_debug("Got xml of "+vm)
		return "Successful"
	
	def get_interfaces(self, domain, vm):
		self.messenger.log_debug("trying to get interfaces of "+vm)
		interfaces = []
		try:
			xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
			xmlDom = parseString(xml)
			domNodes = xmlDom.getElementsByTagName("interface")
			for domNode in domNodes:
				target = {}
				type = domNode.getAttribute('type')
				device = ""
				if type == "bridge" :
					source = domNode.getElementsByTagName("source")[0]
					device = source.getAttribute('bridge')
				elif type == "network":
					source = domNode.getElementsByTagName("source")[0]
					device = source.getAttribute('network')
				elif type == "direct":
					source = domNode.getElementsByTagName("source")[0]
					device = source.getAttribute('dev')
				elif type == "ethernet":
					source = domNode.getElementsByTagName("target")[0]
					device = source.getAttribute('dev')
				elif type == "user":
					source = domNode.getElementsByTagName("mac")[0]
					device = source.getAttribute('address')
				target['type'] = type
				target['source'] = device
				interfaces.append(target)
			
		except:
			self.messenger.log_warning("get interfaces of %s failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot get interfaces of %s: %s" % (vm, str(sys.exc_info()[1]))
			
		self.messenger.log_debug("Got interfaces of "+vm)
		return interfaces
	
	def canMigrate(self, domain, vm):
		result = True
		try:
			xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
			xmlDom = parseString(xml)
			testNodes = xmlDom.getElementsByTagName("metadata")
			if len(testNodes) > 0:
				metaNode = testNodes[0]
				for node in metaNode.childNodes:
					if node.nodeType == node.ELEMENT_NODE and node.tagName == "migration":
						mode = node.getAttributeNode('allowed')
						if mode == "no":
							result = False
			
		except:
			self.messenger.log_error("Check OpenKVI is embeded of %s has failed: %s" % (vm, str(sys.exc_info()[1])))
			return False
		
		return result

	def get_jobinfo(self, domain, vm):
		self.messenger.log_debug("trying to get jobinfo for "+vm)
		jobInfo=[]
		try:
			jobInfo = domain.jobInfo()
		except:
			self.messenger.log_info("get jobinfo of %s failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot get jobinfo for %s: %s" % (vm, str(sys.exc_info()[1]))
		
		infos = {}
		infos["dataTotal"] = jobInfo[3]
		infos["dataProcessed"] = jobInfo[4]
		infos["memTotal"] = jobInfo[6]
		infos["memProcessed"] = jobInfo[7]
		
		self.messenger.log_debug("Got jobinfo for "+vm+": "+str(jobInfo))
		return infos
	
	def screenshot_handler(self, stream, buf, opaque):
		fd = opaque
		os.write(fd, buf)
	
	def take_screenshot(self, image, domain, stream, vm, path):
		""" 
		take a screenshot of a VM and then create thumbnails 
		of different sizes.
		Only called by get_screenshot
		"""
		fd = os.open(image, os.O_WRONLY | os.O_TRUNC | os.O_CREAT, 0644)
		mimetype = domain.screenshot(stream, 0, 0)
		stream.recvAll(self.screenshot_handler, fd)
		os.close(fd)
		#os.system('convert -size 240x134 '+image+' -resize 240x134 '+path+'/'+vm+'-240.png')
		#os.system('convert -size 168x94 '+image+' -resize 168x94 '+path+'/'+vm+'-168.png')
		#os.system('convert -size 120x67 '+image+' -resize 120x67 '+path+'/'+vm+'-120.png')
		#os.system('rm -f /tmp/'+vm+'.dat')
		subprocess.call('convert -size 240x134 '+image+' -resize 240x134 '+path+'/'+vm+'-240.png', shell=True)
		subprocess.call('convert -size 168x94 '+image+' -resize 168x94 '+path+'/'+vm+'-168.png', shell=True)
		subprocess.call('convert -size 120x67 '+image+' -resize 120x67 '+path+'/'+vm+'-120.png', shell=True)
		subprocess.call('rm -f /tmp/'+vm+'.dat', shell=True)
		self.messenger.log_debug("Got screenshot of "+vm)
		return path
	
	def get_screenshot(self, domain, connection, vm, options): 
		""" call take_screenshot """
		self.messenger.log_debug("trying to get screenshot of "+vm)
		image = "/tmp/"+vm+".dat"
		path = "/tmp/screenshots/"
		for option in options:
			if "path" in option:
				args=option.split('=')
				path = args[1].strip()
		if domain.isActive():
			stream = connection.newStream(0)
			try :
				result = self.take_screenshot(image, domain, stream, vm, path)
				#stream.finish()
			except:
				self.messenger.log_info("Failed to get screenshot of %s" % vm)
				result = "Failed: not supported :"+str(sys.exc_info()[1])
			
			del stream
		else:
			self.messenger.log_info("Failed to get screenshot of %s: domain is not active" % vm)
			result = "Failed: domain is not running"
		
		return result
	
	def startMigration(self, vm, conn, destconn, node, destnode, sender, options):
		## Start migration process in a new thread ##
		if self.check_locked(vm, node):
			lock = self.get_lock_name(vm, node)
			return "Error: %s is currently locked by a %s process" % (vm, lock)
		
		res = self.migrate(vm, conn, destconn, node, destnode, sender, options)
		return res
	
	def migrate(self, vm, conn, destconn, node, destnode, sender, options):
		current_thread = threading.currentThread()
		log = {}
		log["vm"] = vm
		log["node"] = node
		log["destination"] = destnode
		log["task"] = "Migration"
		log["sender"] = sender
		log["detail"] = destnode
	
		# Test if VM do not exist on remote node:
		try :
			dom = destconn.lookupByName(vm)
			del dom
			dom_exist = True
		except:
			dom_exist = False
		
		if dom_exist == True:
			self.messenger.log_warning("domain %s already exist on %s !!!" % (vm, destnode))
			return "Error: %s is already defined on destination node %s" % (vm, destnode)
		
		# check lock before doing anything 	
		if self.check_locked(vm, node):
			return "Error: %s is already locked by another user" % vm	
		else:
			self.acquire_lock(vm, node, "Migration", sender)
		
		# Check that network configuration is compatible 
		# Only needed if VM is running
		dom = conn.lookupByName(vm)
		if not self.canMigrate(dom, vm):
			self.messenger.log_warning("domain %s is marked not moveable !" % vm)
			self.release_lock(vm, node, "Migration", sender)
			return "Error: This VM is marked as not moveable."
		
		task = {}
		task['task'] = 'Migration'
		task['vm'] = vm
		task['node'] = node
		task['sender'] = sender
		task['status'] = destnode
		self.add_pending_tasks(task,3600)
		log["event"] = "VM_INFO"
		log["status"] = "Started"
		self.messenger.tell_all("EVENT", log)
		
		activeDomain = dom.isActive()
		interfaces = self.get_interfaces(dom, vm)
		dest_vNetworks = self.get_interfaces(dom, vm)
		del dom
		network_exist = False
		if activeDomain:
			cmd = 'ip link show | grep -v "^  *" |sed -e "s/^[0-9]*: //" | sed -e "s/: .*//"'
			proc = subprocess.Popen(['ssh','-x','root@'+destnode, cmd], stdout=subprocess.PIPE)
			code = proc.wait()
			dest_networks = []
			for aline in proc.stdout:
				dest_networks.append(aline)
			
			vNetwork_list = []
			for a_vNetwork in dest_vNetworks:
				vNetwork_list.append(a_vNetwork['source'])
			
			for an_interface in interfaces:
				source = an_interface['source']
				if (source in dest_networks) or (source in vNetwork_list):
						network_exist = True
					
			if not network_exist:
				self.release_lock(vm, node, "Migration", sender)
				self.messenger.log_warning("target node %s 's network configuration not suitable  for %s !!!" % (destnode, vm))
				return "Error: %s network is not compatible. Cannot proceed to the live migration of %s" % (destnode, vm)
			
		# put information in /etc/hosts of each nodes if needed
		#add_etchosts(node, ip, lines)
		lines = []
		cmd = 'cat /etc/hosts'
		proc = subprocess.Popen(['ssh','-x','root@'+node, cmd], stdout=subprocess.PIPE)
		code = proc.wait()
		for aline in proc.stdout:
			lines.append(aline)
			
		ip = socket.gethostbyname(destnode)
		res, mod = self.add_etchosts(destnode, ip, lines)
		if mod:
			cmd = 'cat << EOF > /etc/hosts\n'+res+'EOF'
			proc = subprocess.Popen(['ssh','-x','root@'+node, cmd], stdout=subprocess.PIPE)
			code = proc.wait()
		def threadedMigration():
			"""
			Move a VM from its current node to destconn
			"""
			interface = None
			rate = 0
			live = True
			secure = False
			progress = False
			newname = None
			flags = 0
			paused = False
			domain = conn.lookupByName(vm)
			self.messenger.log_debug("STARTING MIGRATION OF %s" % vm)
			for option in options:
				if "live" in option:
					args = option.split('=')
					live = args[1].strip()
				elif "rate" in option:
					args = option.split('=')
					rate = args[1].strip()
				elif "interface" in option:
					args = option.split('=')
					interface = args[1].strip()
				elif "secure" in option:
					args = option.split('=')
					secure = args[1].strip()
				elif "newname" in option:
					args = option.split('=')
					newname = args[1].strip()
				elif "progress" in option:
					args = option.split('=')
					progress = args[1].strip()
				
			flags |= libvirt.VIR_MIGRATE_PERSIST_DEST
			flags |= libvirt.VIR_MIGRATE_UNDEFINE_SOURCE
			if secure:
				self.messenger.log_debug("using MIGRATE_PEER2PEER")
				flags |= libvirt.VIR_MIGRATE_PEER2PEER
				flags |= libvirt.VIR_MIGRATE_TUNNELLED
			
			
			vmState = self.get_state(domain, vm, node, None)
			#if vmState["state"] == "suspended":
			# return "Error: cannot migrate suspended domaine !"
			## Check if VM disks are present on remote host ##
			try:
				xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
				xmlDom = parseString(xml)
				domNodes = xmlDom.getElementsByTagName("disk")
				diskList = []
				toRemove = []
				checkoffest = 0
				
				for domNode in domNodes:
					target = {}
					type = domNode.getAttribute('type')
					device = ""
					try: 
						device = domNode.getAttribute('device')
					except:
						device = "unknown"
					
					if type == "file" :
						try:
							source = domNode.getElementsByTagName("source")[0]
							fileAtr = source.getAttribute('file')
						except: 
							fileAtr = ""
						if fileAtr:
							checkoffset = 5
							log["event"] = "VM_PROGRESS"
							log["status"] = "Checking files"
							log["detail"] = checkoffset
							self.messenger.tell_all("EVENT", log)
							sourceLine = "notempty"
							destLine = ""
							if device == "cdrom":
								cmd = 'ls -s '+fileAtr+' 2>/dev/null | sed -e "s/ .*//"'
							else:
								cmd = 'ls -i '+fileAtr+' 2>/dev/null | sed -e "s/ .*//"'
							
							proc = subprocess.Popen(['ssh','-x','root@'+destnode, cmd], stdout=subprocess.PIPE)
							code = proc.wait()
							for aline in proc.stdout:
								destLine += aline
							
							if destLine:
								sourceLine = ""
								proc = subprocess.Popen(['ssh','-x','root@'+node, cmd], stdout=subprocess.PIPE)
								code = proc.wait()
								for aline in proc.stdout:
									sourceLine += aline
								
							self.messenger.log_debug("file type: %s; source: %s; dest: %s" % (device, sourceLine.strip(), destLine.strip()))
							if destLine.strip() != sourceLine.strip():
								target['device'] = device
								target['source'] = fileAtr
								if device == "cdrom":
									diskList.insert(0, target)
								else:
									diskList.append(target)
					
				listLen = len(diskList)
				offset = 0
				if listLen > 0:
					totalSize = 0
					completed = 0
					offset = 90
					oldProgress = ""
					
					for aDisk in diskList:
						cmd = "stat -c %s "+aDisk['source']+" 2>/dev/null"
						proc = subprocess.Popen(['ssh','-x','root@'+node, cmd], stdout=subprocess.PIPE)
						stdout,stderr = proc.communicate()
						tmpSize = ""
						for input in stdout: 
							tmpSize += input
						
						aDisk['size'] = tmpSize.strip()
						totalSize += int(tmpSize.strip())
						
					self.messenger.log_debug("Size to copy from %s to %s: %sM" % (node, destnode, str(totalSize)))
					completed = 0
					suspended = False
					for aDisk in diskList:
						if (aDisk['device'] != "cdrom") and (vmState['state'] == "running") and (suspended != True):
							checkoffset = 10
							log["event"] = "VM_PROGRESS"
							log["detail"] = checkoffset
							log["status"] = "Suspending VM"
							self.messenger.tell_all("EVENT", log)
							self.libvirt_exec(domain, "suspend", vm, node, sender)
							#flags |= libvirt.VIR_MIGRATE_PAUSED
							flags |= libvirt.VIR_MIGRATE_NON_SHARED_INC
							suspended = True
							break
						
					for aDisk in diskList:
						return_code = None
						remoteCmd = 'ssh root@'+node+' "tar cf - '+aDisk["source"]+'" | ssh root@'+destnode+' "tar xf - -C /"'
						proc = subprocess.Popen(remoteCmd, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
						while return_code == None:
							time.sleep(5)
							return_code = proc.poll()
							
							if progress:
								cmd = "stat -c %s "+aDisk['source']+" 2>/dev/null"
								du = subprocess.Popen(['ssh','-x','root@'+destnode, cmd], stdout=subprocess.PIPE)
								stdout,stderr = du.communicate()
								tmpSize = ""
								for input in stdout: 
									tmpSize += input
								
								copied = int(tmpSize.strip())+completed
								intDone = ((copied * 100) // totalSize)
								intProgress = ((offset * intDone) // 100)
								strProgress = str(intProgress+checkoffset)
								#pathList = aDisk['source'].split("/")
								#filename = pathList[-1:]
								if strProgress != oldProgress:
									log["event"] = "VM_PROGRESS"
									log["detail"] = strProgress
									log["status"] = "Moving files"
									self.messenger.tell_all("EVENT", log)
									oldProgress = strProgress
						
						completed += int(aDisk['size'])
						if return_code != 0:
							error = ""
							for line in proc.stderr: 
								error += line
						
							
							log["event"] = "VM_STATUS"
							log["detail"] = "cannot copy disk !"
							log["status"] = "Failed"
							self.messenger.tell_all("EVENT", log)
							self.messenger.log_error("Migration: cannot copy disk %s: %s" % (aDisk["source"], error))
							self.release_lock(vm, node, "Migration", sender)
							return "Error: cannot copy disk %s: %s" % (aDisk["source"], error)
							
						time.sleep(1)
			
			except:
				log["event"] = "VM_STATUS"
				log["detail"] = "cannot get disk information !"
				log["status"] = "Failed"
				self.messenger.tell_all("EVENT", log)
				self.messenger.log_error("Migration: cannot get disk list of %s: %s" % (vm, str(sys.exc_info()[1])))
				self.release_lock(vm, node, "Migration", sender)
				return "Error: cannot get disk list of %s: %s" % (vm, str(sys.exc_info()[1]))
			
			task_aborted = ""
			xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
			if domain.isActive():
				flags |= libvirt.VIR_MIGRATE_LIVE
				if progress:
					if checkoffset > offset:
						offset = checkoffset
					log["task"] = "Migration"
					log["status"] = "Migrating process"
					stop_thread = self.start_migrate_progress_thread(conn, vm, node, log, offset )
				try:
					self.add_pending_tasks({'task':'Started','status':'Migrated','vm':vm,'node':destnode,'sender':sender},300)
					self.add_pending_tasks({'task':'Defined','status':'Added','vm':vm,'node':destnode,'sender':sender},300)
					self.add_pending_tasks({'task':'Resumed','status':'Migrated','vm':vm,'node':destnode,'sender':sender},300)
					self.add_pending_tasks({'task':'Suspended','status':'Paused','vm':vm,'node':destnode,'sender':sender},300)
					self.add_pending_tasks({'task':'Stopped','status':'Migrated','vm':vm,'node':node,'sender':sender},300)
					domain.migrate(destconn, flags, newname, interface, rate)
				except:
					task_aborted = str(sys.exc_info()[1]) 
				try:
					stop_thread.set()
				except:
					self.messenger.log_debug("Failed to set stop event for start_migrate_progress_thread")
			else:
				try:
					task_aborted = ""
					res = self.libvirt_define(destconn, vm, xml, destnode, sender)
					if not res == "Successful":
						task_aborted = res
					else:
						res = self.libvirt_undefine(domain, vm, node, sender)
						if res:
							task_aborted = res
					
				except:
					task_aborted = str(sys.exc_info()[1])
				if task_aborted:
					self.messenger.log_error("Migration: define/undefine of %s has failed: %s" % (vm, task_aborted))
					
				
			task = {}
			task['task'] = 'Migration'
			task['vm'] = vm
			task['node'] = node
			task['sender'] = sender
			task['status'] = destnode
			self.remove_pending_tasks(task)
			
			if task_aborted:
				listLen = len(diskList)
				if listLen > 0:
					for aDisk in diskList:
						self.messenger.log_debug("Deleting %s from %s" % (aDisk['source'], destnode))
						cmd = "rm -f "+aDisk['source']+" 2>/dev/null"
						subprocess.call(['ssh','-x','root@'+destnode, cmd])
				
				vmState = self.get_state(domain, vm, node, None)
				if suspended and vmState['state'] != "running":
					log["event"] = "VM_PROGRESS"
					log["detail"] = ""
					log["status"] = "Resuming Virtual Machine"
					self.messenger.tell_all("EVENT", log)
					res = self.libvirt_exec(domain, "start", vm, node, sender)
					if res != "command sent":
						log["event"] = "VM_STATUS"
						log["task"] = "Started"
						log["status"] = res
						self.messenger.tell_all("EVENT", log)
				
				self.messenger.log_warning("Failed to migrate %s" % vm)
				del domain
				log["event"] = "VM_STATUS"
				log["status"] = "Failed"
				log["detail"] = task_aborted 
				self.messenger.tell_all("EVENT", log)
				self.release_lock(vm, node, "Migration", sender)
				return "Error: cannot migrate %s" % vm
				
			else:
				migratedDomain = destconn.lookupByName(vm)
				vmState = self.get_state(migratedDomain, vm, destnode, None)
				if "Error" in vmState['state']:
					self.messenger.log_info("An error occured when migrating %s to %s!" % (vm, destnode))
					log["event"] = "VM_STATUS"
					log["status"] =  "Error" 
					log["detail"] = destnode
					self.messenger.tell_all("EVENT", log)
				else:
					if suspended and vmState['state'] != "running":
						res = self.libvirt_exec(migratedDomain, "start", vm, destnode, sender)
						if res != "command sent":
							log["event"] = "VM_STATUS"
							log["task"] = "Started"
							log["status"] = res
							self.messenger.tell_all("EVENT", log)
					
					self.messenger.log_info("VM %s successfuly migrated to %s!" % (vm, destnode))
					log["event"] = "VM_STATUS"
					log["status"] =  "Successful" 
					log["detail"] = destnode
					self.messenger.tell_all("EVENT", log)
					
					del domain
					self.release_lock(vm, node, "Migration", sender)
			
			return True
		
		t = threading.Thread(target=threadedMigration, name="migration process", args=())
		t.daemon = True
		t.start()
		return "Migration started"
	
	def start_job_progress_thread(self, domain, vm, node, log):
		current_thread = threading.currentThread()
		def jobinfo_cb():
			self.messenger.log_debug("starting jobinfo_cb")
			while True:
				time.sleep(1)
				
				if not current_thread.isAlive():
					self.messenger.log_debug("thread is not alive")
					return False
				try:
					jobinfo = domain.jobInfo()
					data_tot = float(jobinfo[3])
					data_processed = float(jobinfo[4])
					data_remaining  = float(jobinfo[5])
					data_total = data_processed + data_remaining
						
					# data_total is 0 if the job hasn't started yet
					if not data_total:
						continue
					
					#intProgress = (data_processed/data_total*1000)//10
					intDone = (data_processed/data_total)
					intProgress = (((100*intDone))*10)//10
					strProgress = str(intProgress).strip('.0')
					
					log["event"] = "VM_PROGRESS"
					log["detail"] = strProgress 
					log["status"] = ""
					self.messenger.tell_all("EVENT", log)
				except:
					self.messenger.log_info("Failed to get job info for %s domain does not exist." % vm)
					return False
			
			return True
		
		t = threading.Thread(target=jobinfo_cb, name="job progress reporting", args=())
		t.daemon = True
		t.start()
		self.messenger.log_debug("exiting thread")
	
	def start_migrate_progress_thread(self, conn, vm, node, log, offset = 0):
		current_thread = threading.currentThread()
		stop_thread = threading.Event()
		def jobinfo_cb(stop_event):
			self.messenger.log_debug("starting jobinfo_cb")
			while not stop_event.is_set():
				
				if not current_thread.isAlive():
					self.messenger.log_debug("thread is not alive")
					return False
				try:
					domain = conn.lookupByName(vm)
				except:
					self.messenger.log_debug("Failed to get job info for %s, domain does not exist" % vm)
					return False
				try:
					if domain.isActive():
						jobinfo = domain.jobInfo()
						data_tot = float(jobinfo[3])
						data_processed = float(jobinfo[4])
						data_remaining  = float(jobinfo[5])
						data_total = data_processed + data_remaining
						
						# data_total is 0 if the job hasn't started yet
						if not data_total:
							continue
						
						#intProgress = (data_processed/data_total*1000)//10
						intDone = (data_processed/data_total)
						intProgress = ((offset+((100-offset)*intDone))*10)//10
						strProgress = str(intProgress).strip('.0')
						log["event"] = "VM_PROGRESS"
						log["detail"] = strProgress
						log["status"] = info
						self.messenger.tell_all("EVENT", log)
					del domain
				
				except:
					self.messenger.log_debug("Failed to get jobinfo for %s, cannot follow migration progress." % vm)
					return False
				
				time.sleep(2)
			
			return True
		
		progess_thread = threading.Thread(target=jobinfo_cb, name="job progress reporting", args=(stop_thread,))
		progess_thread.daemon = True
		progess_thread.start()
		return stop_thread

