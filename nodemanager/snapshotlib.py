#!/usr/bin/python -u
"""
Library to control Virtual Machines snapshots
"""

import os
import subprocess
import time
import datetime
import libvirt
import threading
import sys
from xml.dom.minidom import parseString



class SnapshotControler:
	def __init__(self, messenger, vm_handle):
		"""
		Init Controler class
		"""
		self.vm_handle = vm_handle
		self.messenger = messenger
	
	def write_file(self, infile, content):
		""" Common write function """
		f = open(infile, 'w')
		f.write(content)
		f.close()
		dirname = os.path.dirname(infile)
		user = os.stat(dirname).st_uid
		group = os.stat(dirname).st_gid
		os.chown(infile, user, group)
	
	def log_error(self, msg):
		self.messenger.log_error(msg)
	
	def log_warning(self, msg):
		self.messenger.log_warning(msg)
	
	def log_info(self, msg):
		self.messenger.log_info(msg)
	
	def log_debug(self, msg):
		self.messenger.log_debug(msg)

	def getText(self, nodelist):
		rc = []
		for node in nodelist:
			if node.nodeType == node.TEXT_NODE:
				rc.append(node.data)
		return ''.join(rc)

	def vm_state(self, dom):
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
		
		return strState

	def create_checkpoint(self, node, domain, vm, xmlDesc, sender):
		""" Create a checkpoint (snapshot VM state and disks) """
		result = ""
		flags = 0
		log = {}
		log["node"] = node
		log["vm"] = vm
		log["task"] = "Create snapshot"
		log["sender"] = sender
		message = "Creating checkpoint ..."
		try:
			def threadCreateSnapshot():
				job_thread = self.start_snapshot_progress_thread(vm, node, log, message)
				self.vm_handle.acquire_lock(vm, node, "Snapshot", sender)
				try:
					snapshot = domain.snapshotCreateXML(xmlDesc,flags)
					log["event"] = "VM_INFO"
					log["status"] = "Successful"
					log["detail"] = "Checkpoint "+snapshot.getName()+" created"
				except:
					log["event"] = "VM_INFO"
					log["status"] = "Failed"
					log["detail"] = str(sys.exc_info()[1])
					self.log_warning("create checkpoint for %s has failed: %s" % (vm, log["detail"]))
				
				## Set thread's stop event 
				job_thread.set()
				self.vm_handle.release_lock(vm, node, "Snapshot",sender)
				self.messenger.tell_all("EVENT", log)
				
			
		except:
			self.log_warning("create checkpoint for %s has failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot create_checkpoint for %s: %s" % (vm, str(sys.exc_info()[1]))
		
		t = threading.Thread(target=threadCreateSnapshot, name="snapshot creation process", args=())
		t.daemon = True
		t.start()
		return "Snapshot creation started"

	def delete_checkpoint(self, node, domain, vm, sender, options):
		""" delete a checkpoint and merge to parent or children depending of options """
		flags = 0
		nullFlag = 0
		snapName = ""
		log = {}
		log["node"] = node
		log["vm"] = vm
		log["task"] = "Discard snapshot"
		log["sender"] = sender
		message = "Merging snapshot ..."
		for option in options:
			if "snapshot=" in option:
				args=option.split('=')
				snapName = args[1].strip()
			elif "children=" in option:
				args=option.split('=')
				if args[1].strip() == "yes":
					flags |= libvirt.VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN
					log["task"] = "Merge snapshot with parent"
			elif "message=" in option:
				args=option.split('=')
				log["task"] = args[1].strip()
		
		try:
			def threadMergeSnapshot():
				job_thread = self.start_snapshot_progress_thread(vm, node, log, message)
				self.vm_handle.acquire_lock(vm, node, "Snapshot", sender)
				suspended = False
				try:
					if self.vm_state(domain) == "running":
						suspended = True
						domain.suspend()
					
					snapshot = domain.snapshotLookupByName(snapName, nullFlag)
					snapshot.delete(flags)
					detail = "Merged snapshot "+snapName
					status = "Successful"
					## Check if there is no snapshot left 
					## If so cleanup qcow2 image to prevent 
					## ever-growing image bug
					remaining = self.list_snapshots(domain, vm)
					res = ""
					if remaining["list"] == {}:
						if self.vm_state(domain) == "running":
							suspended = True
							domain.suspend()
						res = self.cleanup_image(node, domain, vm)
					
				except:
					## Set thread's stop event 
					job_thread.set()
					status = "Failed"
					detail = str(sys.exc_info()[1])
				
				## Set thread's stop event 
				job_thread.set()
				
				log["event"] = "VM_INFO"
				log["status"] = status
				log["detail"] = detail
				
				if suspended:
					if self.vm_state(domain) == "paused":
						domain.resume()
				self.vm_handle.release_lock(vm, node, "Snapshot", sender)
				self.messenger.tell_all("EVENT", log)
		
		except:
			self.log_warning("deleting checkpoint for %s has failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot create_checkpoint for %s: %s" % (vm, str(sys.exc_info()[1]))
		
		t = threading.Thread(target=threadMergeSnapshot, name="snapshot revert process", args=())
		t.daemon = True
		t.start()
		return "Snapshot merge started"

	def revert_checkpoint(self, node, domain, vm, sender, options):
		""" revert the domain to the given snapshot """
		flags = 0
		nullFlag = 0
		snapName = ""
		log = {}
		log["node"] = node
		log["vm"] = vm
		log["task"] = "Go to snapshot"
		log["sender"] = sender
		message = "Reverting to checkpoint ..."
		
		for option in options:
			if "snapshot=" in option:
				args=option.split('=')
				snapName = args[1].strip()
		
		flags |= libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_FORCE
		#flags |= libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED
		
		try:
			def threadRevertSnapshot():
				job_thread = self.start_snapshot_progress_thread(vm, node, log, message)
				self.vm_handle.acquire_lock(vm, node, "Snapshot", sender)
				suspended = False
				try:
					if self.vm_state(domain) == "running":
						self.log_debug("Revert Snapshot: suspending VM")
						suspended = True
						domain.suspend()
					snapshot = domain.snapshotLookupByName(snapName, nullFlag)
					domain.revertToSnapshot(snapshot, flags)
					detail = "Reverted snapshot "+snapName
					status = "Successful"
					
				except:
					## Set thread's stop event 
					job_thread.set()
					status = "Failed"
					detail = str(sys.exc_info()[1])
				
				## Set thread's stop event 
				job_thread.set()
				
				log["event"] = "VM_INFO"
				log["status"] = status
				log["detail"] = detail
				
				if suspended:
					if self.vm_state(domain) == "paused":
						domain.resume()
				self.vm_handle.release_lock(vm, node, "Snapshot", sender)
				self.messenger.tell_all("EVENT", log)
		
		except:
			self.log_warning("revert checkpoint for %s has failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot create_checkpoint for %s: %s" % (vm, str(sys.exc_info()[1]))
		
		t = threading.Thread(target=threadRevertSnapshot, name="snapshot revert process", args=())
		t.daemon = True
		t.start()
		return "Snapshot revert started"

	def rollback_checkpoint(self, node, domain, vm, sender, options):
		""" rollback the given snapshot """
		log = {}
		log["node"] = node
		log["vm"] = vm
		log["task"] = "Rollback snapshot"
		log["sender"] = sender
		message = "Removing checkpoint ..."
		for option in options:
			if "snapshot=" in option:
				args=option.split('=')
				snapName = args[1].strip()
		try:
			def threadRollbackSnapshot():
				flags = 0
				nullFlag = 0
				job_thread = self.start_snapshot_progress_thread(vm, node, log, message)
				self.vm_handle.acquire_lock(vm, node, "Snapshot", sender)
				suspended = False
				try:
					if self.vm_state(domain) == "running":
						suspended = True
						domain.suspend()
					snapshot = domain.snapshotLookupByName(snapName, nullFlag)
					flags |= libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_FORCE
					#flags |= libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED
					domain.revertToSnapshot(snapshot, flags)
					snapshot.delete(0)
					## Check if there is no snapshot left 
					## If so cleanup qcow2 image to prevent 
					## ever-growing image bug
					remaining = self.list_snapshots(domain, vm)
					res = ""
					if remaining["list"] == {}:
						if self.vm_state(domain) == "running":
							suspended = True
							domain.suspend()
						res = self.cleanup_image(node, domain, vm)
					
					status = "Successful"
					detail = "Checkpoint "+snapName+" rollbacked"
					
				except:
					## Set thread's stop event 
					job_thread.set()
					status = "Failed"
					detail = str(sys.exc_info()[1])
				
				## Set thread's stop event 
				job_thread.set()
				
				log["event"] = "VM_INFO"
				log["status"] = status
				log["detail"] = detail
				
				if suspended:
					if self.vm_state(domain) == "paused":
						domain.resume()
				self.vm_handle.release_lock(vm, node, "Snapshot", sender)
				self.messenger.tell_all("EVENT", log)
		
		except:
			self.log_warning("rollback checkpoint for %s has failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot create_checkpoint for %s: %s" % (vm, str(sys.exc_info()[1]))
		
		t = threading.Thread(target=threadRollbackSnapshot, name="snapshot rollback process", args=())
		t.daemon = True
		t.start()
		return "Snapshot rollback started"
	
	def cleanup_image(self, node, domain, vm):
		""" This is a workaroung to prevent qcow2 images 
		    from ever growing after snapshots cleanup """
		
		result = "Success"
		try: 
			xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
			xmlDom = parseString(xml)
			domNodes = xmlDom.getElementsByTagName("disk")
			diskList = []
			for domNode in domNodes:
				target = {}
				type = domNode.getAttribute('type')
				device = ""
				try: 
					device = domNode.getAttribute('device')
				except:
					device = "unknown"
				
				if type == "file" and device == "disk":
					try:
						source = domNode.getElementsByTagName("source")[0]
						file = source.getAttribute('file')
						driver = domNode.getElementsByTagName("driver")[0]
						drvtype = driver.getAttribute('type')
					except: 
						file = ""
					if file and drvtype == "qcow2":
						cmd = "rm -f "+file+"-cleanup"
						self.messenger.log_debug("cleanup_image %s" % cmd)
						proc = subprocess.Popen(['ssh','-x','root@'+node, cmd], stdout=subprocess.PIPE)
						code = proc.wait()
						for aline in proc.stdout:
							destLine += aline
						
						cmd = "qemu-img convert -f qcow2 -O qcow2 %s %s-cleanup" % (file ,file)
						self.messenger.log_debug("cleanup_image %s" % cmd)
						proc = subprocess.Popen(['ssh','-x','root@'+node, cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
						code = proc.wait()
						if code != 0:
							return "Error: %s" % proc.stderr
						else:
							cmd = "rm -f %s; mv -f %s-cleanup %s" % (file, file, file)
							self.messenger.log_debug("cleanup_image %s" % cmd)
							proc = subprocess.Popen(['ssh','-x','root@'+node, cmd], stdout=subprocess.PIPE)
							code = proc.wait()
							for aline in proc.stdout:
								destLine += aline
		except:
			return "Error: " % str(sys.exc_info()[1])
		
		return result


	def get_current(self, domain, vm):
		""" get current checkpoint """
		result = ""
		flags = 0
		try:
			snapshot = domain.snapshotCurrent(flags)
			result = snapshot.getName()
		except:
			self.log_info("get current snapshot for %s has failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot get_current for %s: %s" % (vm, str(sys.exc_info()[1]))
		
		return result

	def list_snapshots(self, domain, vm):
		""" list all snapshots """
		result = {}
		result["list"] = {}
		result["current"] = ""
		snaplist = []
		tmp = {}
		flags = 0
		try:
			snapList = domain.snapshotListNames(flags)
			for snapName in snapList:
				res = {}
				snapshot = domain.snapshotLookupByName(snapName, flags)
				try: 
					parent = snapshot.getParent(flags)
					parentName = parent.getName()
				except: 
					parentName = "no parent"
				
				xmlString = snapshot.getXMLDesc(flags)
				xmlDom = parseString(xmlString)
					
				nodeTime = xmlDom.getElementsByTagName("creationTime")[0]
				creationTime = self.getText(nodeTime.childNodes)
				aTime = datetime.datetime.fromtimestamp(int(creationTime)).strftime('%Y-%m-%d %H:%M:%S')
				
				try:
					nodeDesc = xmlDom.getElementsByTagName("description")[0]
					description = self.getText(nodeDesc.childNodes)
				except:
					description = "none"
				
				res["parent"] = parentName
				res["date"] = aTime
				res["description"] = description
				res["children"] = {}
				tmp[snapName] = res
				snaplist.append(snapName)
			
			tmpList = snaplist[::-1]
			for item in tmpList:
				desc = {}
				parentName = tmp[item]["parent"]
				if parentName != "no parent" : 
					parentName = tmp[item]["parent"]
					del tmp[item]["parent"]
					tmp[parentName]["children"][item] = tmp[item]
				else:
					del tmp[item]["parent"]
					result["list"][item] = tmp[item]
			
			if len(snaplist) > 0:
				result["current"] = self.get_current(domain, vm)
				
		except:
			self.log_info("list snapshots for %s has failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot list_snapshots for %s: %s" % (vm, str(sys.exc_info()[1]))
		
		self.messenger.log_debug("snapshots list: %s" % result)
		return result

	def get_snapshotXml(self, domain, vm, name):
		""" get current checkpoint """
		result = ""
		flags = 0
		try:
			snapshot = domain.snapshotLookupByName(name, flags)
			flags |= libvirt.VIR_DOMAIN_XML_SECURE
			xmlString = snapshot.getXMLDesc(flags)
			result = xmlString
		except:
			self.log_warning("get snapshot Xml for %s has failed: %s" % (vm, str(sys.exc_info()[1])))
			return "Error: cannot get_snapshotXml for %s: %s" % (vm, str(sys.exc_info()[1]))
		
		return result


	def start_snapshot_progress_thread(self, vm, node, log, message):
		current_thread = threading.currentThread()
		stop_thread = threading.Event()
		self.log = log
		def jobinfo_cb(stop_event):
			self.messenger.log_debug("starting jobinfo_cb")
			while not stop_event.is_set():
				if not current_thread.isAlive():
					self.messenger.log_debug("thread is not alive")
					return False
				
				strProgress = "-1"
				self.log["event"] = "VM_PROGRESS"
				self.log["detail"] = strProgress
				self.log["status"] = message
				self.messenger.tell_all("EVENT", self.log)
				#self.messenger.tell_all("EVENT;VM_PROGRESS;;%s;;%s;;%s;;%s;;%s" % (node , vm, progtext, strProgress, info))
				time.sleep(2)
			
			return True
		progess_thread = threading.Thread(target=jobinfo_cb, name="job progress reporting", args=(stop_thread,))
		progess_thread.daemon = True
		progess_thread.start()
		return stop_thread
