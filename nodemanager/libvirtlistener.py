#!/usr/bin/python -u

import libvirt
import threading
import sys
from switchlib import switch

class Listener:
	def __init__(self, messenger, vm_handle):
		self.messenger = messenger
		self.eventLoopThread = None
		self.running = True
		self.vm_handle = vm_handle
		self.nodes = {}
		self.nodeLib = None
	
	def virEventLoopNativeRun(self):
		while self.running:
			try:
				libvirt.virEventRunDefaultImpl()
			except:
				break
	
	def virEventLoopNativeStart(self):
		libvirt.virEventRegisterDefaultImpl()
		#eventLoopName = self.node+"EventLoop"
		self.eventLoopThread = threading.Thread(target = self.virEventLoopNativeRun, name="libvirtEventLoop")
		self.eventLoopThread.setDaemon(True)
		self.eventLoopThread.start()
	
	def eventToString(self, event):
		eventStrings = ( "Defined",
				 "Undefined",
				 "Started",
				 "Suspended",
				 "Resumed",
				 "Stopped",
				 "Shutdown")
		return eventStrings[event]
	
	def detailToString(self, event, detail):
		eventStrings = (
			( "Added", "Updated", "Unknown" ),
			( "Removed", "Unknown" ),
			( "Booted", "Migrated", "Restored", "Snapshot", "Wakeup" ),
			( "Paused", "Migrated", "IOError", "Watchdog", "Restored", "Snapshot" ),
			( "Unpaused", "Migrated", "Snapshot" ),
			( "Shutdown", "Destroyed", "Crashed", "Migrated", "Saved", "Failed", "Snapshot" ),
			( "Finished", "Unknown" )
			)
		return eventStrings[event][detail]
	
	def domainEventCallback (self, conn, dom, event, detail, opaque):
		task = self.eventToString(event)
		status = self.detailToString(event, detail)
		vm = dom.name()
		self.messenger.log_event("%s %s %s" % (vm, task, status))
		sendMsg = True
		sender = "Node Manager"
		node = self.nodes[str(conn)]
		log = {}
		log["node"] = node
		log["event"] = "VM_STATUS"
		log["vm"] = vm
		log["task"] = task
		log["status"] = status
		taskInfo = self.vm_handle.get_task_infos(log)
		if taskInfo.has_key("sender"):
			log["sender"] = taskInfo["sender"]
			sender = taskInfo["sender"]
		if taskInfo.has_key("send_msg"):
			log["send_msg"] = taskInfo["send_msg"]
			sendMsg = taskInfo["send_msg"]
		
		for case in switch(task):
			if case("Stopped"):
				self.vm_handle.stop_websocket(log["vm"], node)
				self.nodeLib.update_node_bridges_infos(node)
				if log["status"] == "Migrated":
					self.vm_handle.remove(log["vm"], node, sender, None)
					sendMsg = False
				break
				
			if case("Started"):
				self.nodeLib.update_node_bridges_infos(node)
				break
				
			if case("Defined"):
				if log["status"] == "Added":
					self.vm_handle.add(log["vm"], node, dom, sender)
					sendMsg = False
				elif log["status"] == "Updated":
					self.vm_handle.vm_updated(log)
					sendMsg = False
				break
				
			if case("Undefined"):
				self.vm_handle.db.remove_vm(vm, node)
				# sendMsg = False
				break
				
			if case("Shutdown"):
				# Shutdown is not a usefull event
				sendMsg = False
				break
		
		print log
		if sendMsg == True:
			self.messenger.tell_all("EVENT", log)
		self.vm_handle.remove_pending_tasks(log)
	
	
	def domainEventCallback1(self,conn, dom, event, detail, opaque):
		print "domainEventCallback1 EVENT: Domain %s(%s) %s %s" % (dom.name(), dom.ID(), self.eventToString(event), self.detailToString(event, detail))
	
	
	def stop(self):
		self.running = False
	
	def startloop(self):
		# Run a background thread with the event loop
		self.virEventLoopNativeStart()
	
	def register(self, conn, node):
		#self.vc.domainEventRegister(self.domainEventCallback, None)
		self.nodes[str(conn)] = node
		conn.domainEventRegister(self.domainEventCallback, None)
	
	def unregister(self, conn):
		try :
			del self.nodes[str(conn)]
			conn.domainEventDeregister(self.domainEventCallback)
			result = "unregistered"
		except:
			result = str(sys.exc_info()[1])
		
		return result
	
