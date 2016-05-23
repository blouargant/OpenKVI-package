#!/usr/bin/python -u
# VERSION=0.0.1-rc1
#
# command syntaxe:
# { sender : user_name,		# user sending the command
#   target : "NODE" | "VM", 	# command type
#   node   : node_name,		# node to send the command to
#   action*: { }		# json structure as follow:
# }
#
# (*) action for target = "NODE" :
#	{ name     : "add"|"remove"... ,	# action name
#	  driver   : "kvm"|"esx"|"xen"... ,	# driver typr
#	  transport: "ssh"|"tls",
#	  options  : []				# list of options, can be empty			
#						eg: ["192.168.0.1", "exchange_keys"]
#	}
#
# (*) action for target = "VM" :
#	{ name    : "start"|"stop"...,# action name
#	  vm      : vm_name,
#	  options : []  # list of options, an be empty
#
# VMs suported actions : start, stop, kill, reboot, add, remove, suspend, resume,
# 			save, restore, update, autostart
#
#

import os
import SocketServer
import time
import threading
import sys
import re
import json
import subprocess
from vmlib import VMSControler
from nodelib import NodesControler
from messengerlib import MSGControler
from postgreslib import PGSQLControler
from snapshotlib import SnapshotControler
from switchlib import switch
import libvirtlistener

class TimeoutError(Exception):
	def __init__(self, value = "timeout"):
		self.value = value
	def __str__(self):
		return repr(self.value)
	pass


class handleConnection(SocketServer.BaseRequestHandler):

	def timelimit(timeout):
		def internal(function):
			def internal2(*args, **kw):
				class Calculator(threading.Thread):
					def __init__(self):
						threading.Thread.__init__(self)
						self.result = None
						self.error = None
					
					def run(self):
						try:
							self.result = function(*args, **kw)
						except:
							self.error = sys.exc_info()[0]
				
				c = Calculator()
				c.start()
				c.join(timeout)
				if c.isAlive():
					raise TimeoutError
				if c.error:
					raise c.error
				return c.result
			return internal2
		return internal
	
	def handle(self):
		self.messenger = messenger
		self.vmClass = vmClass
		self.nodeClass = nodeClass

		data = self.request[0].strip()
		client_socket = self.request[1]
		res = self.handle_command(data)
		try :
			client_socket.sendto(res, self.client_address)
		except:
			self.messenger.log_error("%s is not listening" % self.client_address)

	def handle_command(self, line):
		result = ""
		try:
			data = json.loads(line)
			sender = data["sender"]
			target = data["target"]
			action_dic = data["action"]
			send_all = True
			self.messenger.print_debug("RECEIVED COMMAND: "+line)
			
			for case in switch(target):
				if case("GENERAL"):
					send_all, res = self.handle_general_command(data)
					break
				
				if case("NODE"):
					send_all, res = self.handle_node_command(data)
					break
				
				if case("VM"):
					send_all, res = self.handle_vm_command(data)
					break
				
				if case("SNAPSHOT"):
					send_all, res = self.handle_snapshot_command(data)	
					self.messenger.print_debug("SNAPSHOT RESULT: %s" % res)
					break
			
			data["action"]["result"] = res
			result = json.dumps(data)
			self.messenger.print_debug("COMMAND RESULT: "+result)
			
			if send_all :
				self.messenger.tell_all("CONTROL "+target , data)
		except:
			err = str(sys.exc_info()[1])
			self.messenger.print_debug("handle command request: "+line)
			self.messenger.print_debug("handle result exception: "+err)
		
		return result 
	
	### HANDLE GENERAL REQUESTS ###
	def handle_general_command(self, data):
		send_all = False
		res = ""
		sender = data["sender"]
		#target = data["target"]
		action_dic = data["action"]
		action_name = action_dic["name"]
		options = action_dic["options"]
			
		for case in switch(action_name):
			if case("restartOpenkvi"):
				res = os.system("service tomcat restart")
				break
			if case("get_debug"):
				if self.messenger.debug == True :
					res = "yes"
				else:
					res = "no"
				break
			if case("set_debug"):
				res = action_dic["enabled"]
				if res == "yes":
					configDic["debug"] = True
					self.messenger.debug = True
				else:
					configDic["debug"] = False
					self.messenger.debug = False
				send_all = True
				break
			if case("get_security_level"):
				res = configDic["security"]
				break
			if case("set_security_level"):
				configDic["security"] = action_dic["level"]
				self.messenger.security = action_dic["level"]
				fconfig = open(configFile, 'r')
				read_lines = fconfig.readlines()
				fconfig.close()
				write_lines = []
				for aline in read_lines:
					if not re.search("^ *#", aline) :
						config_args = aline.split('=')
						if "security" in config_args[0]:
							aline = "security="+action_dic["level"]+"\n"
					write_lines.append(aline)
				fconfig = open(configFile, 'w')
				fconfig.writelines(write_lines)
				fconfig.close()
				level = action_dic["level"]
				for case in switch(level):
					if case("low"):
						os.system("sh /etc/nodemanager/iptables/unset-firewall.sh")
						#res = os.system("\cp -f /etc/nodemanager/nginx/openkvi_nginx_unsecure.conf /etc/nginx/conf.d/openkvi_nginx_default.conf")
						break
					if case("high"):
						os.system("sh /etc/nodemanager/iptables/set-firewall.sh")
						#res = os.system("\cp -f /etc/nodemanager/nginx/openkvi_nginx_secure.conf /etc/nginx/conf.d/openkvi_nginx_default.conf")
				
				# Force SSL by default
				res = os.system("\cp -f /etc/nodemanager/nginx/openkvi_nginx_secure.conf /etc/nginx/conf.d/openkvi_nginx_default.conf")
				res = os.system("\cp -f /etc/nodemanager/nginx/openkvi_nginx_ssl.conf /etc/nginx/conf.d/openkvi_nginx_ssl.conf")
				os.system("service nginx reload")
				
				for node in self.nodeClass.nlist.keys():
					self.vmClass.clearAllWebsockets(node)
			
				res = "done"
				send_all = True
				self.messenger.running = False
		
		return send_all, res
	
	### HANDLE HOSTING NODES REQUESTS ###
	def handle_node_command(self, data):
		""" Handle commands targeted to self.nodeClass """
		res = ""
		sender = data["sender"]
		target = data["target"]
		node = data["node"]
		action_dic = data["action"]
		send_all = True
		action_name = action_dic["name"]
		options = action_dic["options"]
		request = ""
		try:
			for case in switch(action_name):
				if case("add"):
					driver = action_dic["driver"]
					transport = action_dic["transport"]
					description = action_dic["description"]
					res = self.node_add(sender, node, driver, transport, description, options)
					if ("Failed" in res['state']) or ("Failed" in res):
						send_all = False
					break
				
				if case("connect"):
					res = self.node_test_connection(node, False)
					send_all = False
					break
				
				if case("reconnect"):
					res = self.node_test_connection(node, True)
					break
				
				if case("remove"):
					if node in inactive_nodes:
						inactive_nodes.remove(node)
					res = self.nodeClass.remove(node)
					break
				
				if case("get"):
					send_all = False
					request = action_dic["request"]
					self.messenger.print_debug("request: %s" % request)
					if request == "screenshots":
						res = self.node_get_vm_screenshots(node, options)
					elif request == "etchosts":
						res = self.nodeClass.read_etchosts()
					else :
						res = self.node_get(node, request, options)
					break
				
				if case("list_directory"):
					send_all = False
					path = action_dic["request"]
					res = self.nodeClass.list_directory(node, path)
					break
				
				if case("file_info"):
					send_all = False
					path = action_dic["request"]
					res = self.nodeClass.get_file_info(node, path)
					break
				
				if case("notify"):
					res = json.loads(action_dic["infos"])
					send_all = True
					break
				
				if case("network"):
					request = action_dic["request"]
					desc = action_dic["desc"]
					if request == "create":
						res = self.nodeClass.create_network(node, desc)
					elif request == "update" :
						res = self.nodeClass.update_network(node, desc)
					elif request == "remove" :
						res = self.nodeClass.remove_network(node, desc)
					elif request == "vmnics" :
						res = self.nodeClass.list_active_vmnics(node)
						send_all = False
					break
				
				if case("vnic_ip"):
					send_all = False
					vm = action_dic["vm"]
					mac = action_dic["mac"]
					ip_range = action_dic["range"]
					res = self.nodeClass.find_vnic_ip(node, vm, mac, ip_range)
					break
				
				if case("set"):
					send_all = False
					request = action_dic["request"]
					desc = action_dic["desc"]
					if request == "time":
						res = self.nodeClass.set_node_time(node, desc, options)
					elif request == "timeservers":
						res = self.nodeClass.set_node_timeserver(node, desc, options)
					elif request == "timemisc":
						res = self.nodeClass.set_node_timemisc(node, desc, options)
					elif request == "etchosts":
						res = self.nodeClass.write_etchosts(desc)
					elif request == "snmp":
						res = self.nodeClass.set_node_snmp_config(node, desc)
					elif request == "ipmi":
						res = self.nodeClass.set_node_ipmi_config(node, desc)
					break
				
				if case("local_import"):
					data = action_dic["data"]
					res = self.nodeClass.local_import(node, data, options)
		
		except:
			err = str(sys.exc_info()[1])
			self.messenger.log_error("%s request %s has failed: %s" % (node, action_name, err))
			res = "Failed: " + err
		
		return send_all, res
	
	
	@timelimit(40)
	def node_add(self, sender, node, driver, transport, description, options):
		result = self.nodeClass.add(sender, node, driver, transport, description, options)
		return result
	
	@timelimit(20)
	def node_test_connection(self, node, force):
		result = self.nodeClass.test_connection(node, force)
		return result
	
	@timelimit(40)
	def node_get_vm_screenshots(self, node, options):
		result = self.nodeClass.get_vm_screenshots(node, options)
		return result
	
	@timelimit(20)
	def node_get(self, node, request, options):
		result = self.nodeClass.get(node, request, options)
		return result
	
	
	### HANDLE VIRTUAL MACHINES REQUESTS ###
	def handle_vm_command(self, data):
		send_all = False
		res = ""
		sender = data["sender"]
		target = data["target"]
		node = data["node"]
		action_dic = data["action"]
		action_name = action_dic["name"]
		vm = action_dic["vm"]
		options = action_dic["options"]
		
		self.nodeClass.nlock.acquire_read()
		if self.nodeClass.nlist.has_key(node):
			conn = self.nodeClass.nlist[node]["connection"]
			self.nodeClass.nlock.release()
		else:
			self.nodeClass.nlock.release()
			self.messenger.log_error("%s %s@%s failed: unknown error" % (action_name, vm, node))
			res = "Error: unknown node "+node
		
		## Remove VM from database
		if (action_name == "remove"):
			res = self.vm_remove(vm, node, sender, options)
			send_all = False
			return send_all, res
		
		domain_excluded = [ "define", "check", "remove", "create_vdisk", "delete_vdisk"]
		if action_name not in domain_excluded:
			try:
				domain = conn.lookupByName(vm)
			except: 
				self.messenger.log_warning("%s %s@%s failed: no such Virtual Machine" % (action_name, vm, node))
				res = {}
				res["state"] = "Error: vm does not exist"
				res["locked"] = False
				return send_all, res

			vmlocked = self.vmClass.check_locked(vm, node)
			lockName = ""
			if vmlocked and action_name != "get":
				lockName = self.vmClass.get_lock_name(vm, node)
				self.messenger.log_warning("Prohibited: %s@%s is locked by %s" % (vm, node, lockName))
				res = "Prohibited: Virtual machine is locked by "+lockName+" process"
				return send_all, res
							
		maxretries = 2
		retries = 0
		while retries < maxretries:
			try:
				for case in switch(action_name):
					if case("get"):
						request = action_dic["request"]
						if request == "state":
							res = self.vm_get(domain, request, vm, node, options)
						elif not vmlocked:
							if request == "screenshot":
								retries = maxretries
								res = self.vm_get_screenshot(domain, conn, vm, options)
							elif request == "vnics":
								res = self.vm_get_vnics(node, domain)
							elif request == "display":
								if self.messenger.security == "low":
									offset = 0
								else:
									port = self.nodeClass.nlist[node]["webshell"]["port"]
									offset = (int(port)-4201+10)*1000
								res = self.vm_get_websocket(vm, domain, node, offset)
							else:
								res = self.vm_get(domain, request, vm, node, options)
							
							notify = "no"
							for option in options: 
								if "notify" in option:
									args = option.split('=')
									notify = args[1].strip()
							if (notify == "yes"):
								send_all = True
								action_dic["name"] = "Import virtual machine"
						else:
							self.messenger.log_warning("Prohibited: %s@%s is locked by %s" % (vm, node, lockName))
							res = "Prohibited: Virtual machine is locked by "+lockName+" process"
							return send_all, res
						break
					
					if case("send"):
						request = action_dic["request"]
						send_all = False
						if request == "shutdown":
							retries = maxretries
						res = self.vm_send(domain, request, vm, node, sender, options)
						break
					
					if case("undefine"):
						retries = maxretries
						res = self.vm_undefine(domain, vm, node, sender)
						break
					
					if case("define"):
						retries = maxretries
						xml = action_dic["xml"]
						res = self.vm_define(conn, vm, xml, node, sender)
						data["action"]["xml"] = ""
						break
					
					if case("update"):
						xml = action_dic["xml"]
						device = action_dic["device"]
						res = self.vm_update_conf(conn, vm, xml, node, sender, device)
						break
					
					if case("live_update"):
						xml = action_dic["xml"]
						self.messenger.print_debug("device to update: "+xml)
						send_all = False
						if domain.isActive():
							res = self.vm_live_update_device(node, vm, domain, xml, sender, options)
						break
					
					if case("move_vnic"):
						vnic = json.loads(action_dic["vnic"])
						send_all = False
						res = self.vm_move_vnic(node, vm, domain, vnic, sender, options)
						break
					
					if case("move_vlink"):
						vlink = json.loads(action_dic["vlink"])
						send_all = False
						res = self.vm_move_vlink(node, vm, domain, vlink, sender, options)
						break
					
					if case("link_state"):
						link = json.loads(action_dic["link"])
						send_all = False
						res = self.vm_change_link_state(node, vm, domain, link, sender, options)
						break
					
					if case("create_vdisk"):
						retries = maxretries
						vdisk = action_dic["vdisk"]
						self.messenger.print_debug("create vdisk: %s" % vdisk)
						send_all = False
						res = self.vm_create_vdisk(vm, node, vdisk, sender, options)
						break
					
					if case("delete_vdisk"):
						retries = maxretries
						vdisk = action_dic["vdisk"]
						self.messenger.print_debug("delete vdisk: %s" % vdisk)
						send_all = False
						res = self.vm_delete_vdisk(vm, node, vdisk, sender, options)
						break
					
					if case("vdisk_info"):
						retries = maxretries
						vdisk = action_dic["vdisk"]
						send_all = False
						res = self.vm_get_vdisk_info(vm, node, vdisk, sender, options)
						break
					
					if case("erase_vdisk"):
						retries = maxretries
						vdisk = action_dic["vdisk"]
						self.messenger.print_debug("erase vdisk: %s" % vdisk)
						send_all = False
						res = self.vm_erase_vdisk(domain, vm, node, vdisk, sender, options)
						break
					
					if case("migrate"):
						send_all = False
						destnode = action_dic["dest"]
						self.nodeClass.nlock.acquire_read()
						if self.nodeClass.nlist.has_key(destnode):
							destconn = self.nodeClass.nlist[destnode]["connection"]
							self.nodeClass.nlock.release()
							res = self.vmClass.startMigration(vm,conn, destconn, node, destnode, sender, options)
						else:
							self.nodeClass.nlock.release()
							res = "Error: unknown node "+destnode
						break
					
					if case("check"):
						send_all = False
						request = action_dic["request"]
						if request == "exist":
							res = self.check_vm_exit(conn, vm)
						break
					
					if case("virtop"):
						send_all = False
						res = self.vmClass.virtop(vm, node)
						break
					
					if case():
						send_all = False
						self.messenger.print_debug("Unknown request: %s" % action_name)
						res = "Error: unknown request "+action_name
				
				retries = maxretries
			
			except:
				err = str(sys.exc_info()[1])
				self.messenger.print_debug("%s: request error = %s" % (vm, err))
				self.messenger.print_debug("Request: %s" % data)
				retries = retries + 1
				res = "Failed: "+err
		
		if (action_name != "define") and (action_name != "check"):
			if domain:
				del domain
		return send_all, res
	
	@timelimit(20)
	def vm_get_screenshot(self, domain, conn, vm, options):
		result = self.vmClass.get_screenshot(domain, conn, vm, options)
		return result
	
	@timelimit(20)
	def vm_get(self, domain, request, vm, node, options):
		result = self.vmClass.get(domain, request, vm, node, options)
		return result
	
	@timelimit(20)
	def vm_get_websocket(self, vm, domain, node, offset):
		result = self.vmClass.get_websocket(vm, domain, node, offset)
		return result
	
	@timelimit(25)
	def vm_send(self, domain, request, vm, node, sender, options):
		result = self.vmClass.send(domain, request, vm, node, sender, options)
		return result
		
	@timelimit(20)
	def vm_undefine(self, domain, vm, node, sender):
		result = self.vmClass.undefine(domain, vm, node, sender)
		return result
	
	@timelimit(20)
	def vm_remove(self, vm, node, sender, options):
		result = self.vmClass.remove(vm, node, sender, options)
		return result
	
	@timelimit(25)
	def vm_define(self, conn, vm, xml, node, sender):
		result = self.vmClass.define(conn, vm, xml, node, sender)
		return result
	
	@timelimit(20)
	def vm_update_conf(self, conn, vm, xml, node, sender, device):
		result = self.vmClass.update_conf(conn, vm, xml, node, sender, device)
		return result
	
	@timelimit(20)
	def vm_move_vnic(self, node, vm, domain, vnic, sender, options):
		result = ""
		try:
			pending_task = {}
			pending_task['task'] = 'Defined'
			pending_task['status'] = 'Updated'
			pending_task['vm'] = vm
			pending_task['node'] = node
			pending_task['sender'] = sender
			pending_task['show_task'] = 'Move Virtual NIC'
			self.vmClass.add_pending_tasks(pending_task, 300)
			network_list = []
			network_list.append(vnic)
			result = self.nodeClass.move_vm_networks(node, vm, network_list)
		except:
			err = str(sys.exc_info()[1])
			self.messenger.print_debug("VNIC migration error : %s" %  err)
			result = "Error: "+err
		return result
	
	@timelimit(20)
	def vm_move_vlink(self, node, vm, domain, vlink, sender, options):
		result = ""
		try:
			if domain.isActive():
				domain_vnic_list = self.nodeClass.get_active_domain_extended_vnics(node, domain)
				for dom_vnic in domain_vnic_list['vnics']:
					if dom_vnic['mac'] == vlink['mac']:
						src_dict = {}
						dst_dict = {}
						src_dict['vnic'] = dom_vnic['target']
						src_dict['bridge'] = dom_vnic['source']
						src_dict['state'] = dom_vnic['state']
						dst_dict['type'] = dom_vnic['type']
						dst_dict['vswitch'] = vlink['vswitch']
						dst_dict['portgroup'] = vlink['portgroup']
						dst_dict['state'] = dom_vnic['state']
						result = self.nodeClass.move_vnic_link(node, src_dict, dst_dict)
			else:
				result = "Error: domain is not active"
		except:
			err = str(sys.exc_info()[1])
			self.messenger.print_debug("Link state modification error : %s" %  err)
			result = "Error: "+err
		return result
	
	@timelimit(20)
	def vm_change_link_state(self, node, vm, domain, link, sender, options):
		result = ""
		try:
			if domain.isActive():
				domain_vnic_list = self.nodeClass.get_active_domain_extended_vnics(node, domain)
				for dom_vnic in domain_vnic_list['vnics']:
					if dom_vnic['mac'] == link['mac']:
						if dom_vnic['state'] != link['state']:
							src_dict = {}
							dst_dict = {}
							src_dict['vnic'] = dom_vnic['target']
							src_dict['bridge'] = dom_vnic['source']
							src_dict['state'] = dom_vnic['state']
							dst_dict['type'] = dom_vnic['type']
							dst_dict['vswitch'] = dom_vnic['vswitch']
							dst_dict['portgroup'] = dom_vnic['portgroup']
							dst_dict['state'] = link['state']
							result = self.nodeClass.move_vnic_link(node, src_dict, dst_dict)
			else:
				result = "Error : domain is not active"
		except:
			err = str(sys.exc_info()[1])
			self.messenger.print_debug("Link state modification error : %s" %  err)
			result = err
		return result
	
	@timelimit(20)
	def vm_live_update_device(self, node, vm, domain, xml, sender, options):
		result = ""
		try:
			result = self.vmClass.live_update_device(domain, vm, node, xml, sender, options)
		except:
			err = str(sys.exc_info()[1])
			self.messenger.print_debug("VM live update error : %s" %  err)
			result = err
		
		return result
	
	@timelimit(20)
	def vm_create_vdisk(self, vm, node, vdisk, sender, options):
		result = self.nodeClass.create_vdisk(vm, node, vdisk, sender, options)
		return result
	
	@timelimit(20)
	def vm_delete_vdisk(self, vm, node, vdisk, sender, options):
		result = self.nodeClass.delete_vdisk(vm, node, vdisk, sender, options)
		return result
	
	@timelimit(20)
	def vm_get_vdisk_info(self, vm, node, vdisk, sender, options):
		result = self.nodeClass.get_vdisk_info(vm, node, vdisk, sender, options)
		return result
	
	@timelimit(60)
	def vm_erase_vdisk(self, domain, vm, node, vdisk, sender, options):
		result = self.nodeClass.erase_vdisk(domain, vm, node, vdisk, sender, options)
		return result
	
	def check_vm_exit(self, conn, vm):
		result = ""
		try :
			if conn.lookupByName(vm):
				result = vm
			else:
				result = "not found"
				self.messenger.print_debug("vm not found")
		except:
			self.messenger.print_debug("exception, vm not found")
			result = "not found"
		return result
	
	@timelimit(20)
	def vm_get_vnics(self, node, domain):
		result = []
		try:
			result = self.nodeClass.get_active_domain_extended_vnics(node, domain)
		except:
			err = str(sys.exc_info()[1])
			self.messenger.print_debug("Cannot get active network information: %s" % err)
		return result
	
	### HANDLE SNAPSHOTS REQUESTS ###
	def handle_snapshot_command(self, data):
		send_all = False
		res = ""
		sender = data["sender"]
		target = data["target"]
		node = data["node"]
		action_dic = data["action"]
		action_name = action_dic["name"]
		vm = action_dic["vm"]
		options = action_dic["options"]
		
		self.nodeClass.nlock.acquire_read()
		if self.nodeClass.nlist.has_key(node):
			conn = self.nodeClass.nlist[node]["connection"]
			self.nodeClass.nlock.release()
		else:
			self.nodeClass.nlock.release()
			self.messenger.log_error("%s %s@%s failed: unknown error" % (action_name, vm, node))
			res = "Error: unknown node "+node
		
		try:
			domain = conn.lookupByName(vm)	
		except: 
			self.messenger.log_warning("%s %s@%s failed: no such Virtual Machine" % (action_name, vm, node))
			res = "Error: vm does not exist"
			return send_all, res
		
		# Check if VM is locked 
		# return an error if locked 
		vmlocked = self.vmClass.check_locked(vm, node)
		if vmlocked:
			res = "Error: Virtual machine is locked"
			return send_all, res
		
		self.snapshots = snapshot_handle
		try:
			for case in switch(action_name):
				if case("create"):
					xml = action_dic["xml"]
					res = self.snapshot_create(node, domain, vm, xml, sender, options)
					break
				if case("list"):
					self.messenger.print_debug("get snapshots for "+vm)
					res = self.snapshot_list(domain, vm, options)
					break
				if case("current"):
					res = self.snapshot_get_current(domain, vm, options)
					break
				if case("delete"):
					res = self.snapshot_delete(node, domain, vm, sender, options)
					break
				if case("rollback"):
					res = self.snapshot_rollback(node, domain, vm, sender, options)
					break
				if case("revert"):
					res = self.snapshot_revert(node, domain, vm, sender, options)
		
		except:
			err = str(sys.exc_info()[1])
			self.messenger.print_debug("%s: request error = %s" % (vm, err))
			res = "Failed: "+err
			send_all = True
		
		del domain
		return send_all, res
	
	@timelimit(1800)
	def snapshot_create(self,node, domain, vm, xml, sender, options):
		result = self.snapshots.create_checkpoint(node, domain, vm, xml, sender)
		return result
	
	@timelimit(1800)
	def snapshot_delete(self, node, domain, vm, sender, options):
		result = self.snapshots.delete_checkpoint(node, domain, vm, sender, options)
		return result

	@timelimit(1800)
	def snapshot_rollback(self, node, domain, vm, sender, options):
		result = self.snapshots.rollback_checkpoint(node, domain, vm, sender, options)
		return result
	
	@timelimit(1800)
	def snapshot_revert(self, node, domain, vm, sender, options):
		result = self.snapshots.revert_checkpoint(node, domain, vm, sender, options)
		return result
	
	@timelimit(20)
	def snapshot_list(self, domain, vm, options):
		result = self.snapshots.list_snapshots(domain, vm)
		return result
	
	@timelimit(20)
	def snapshot_get_current(self, domain, vm, options):
		result = self.snapshots.get_current(domain, vm)
		self.messenger.print_debug("got current snapshot for "+vm)
		return result

### END class handleConnection ###



def str_to_bool(s):
	if s == 'True':
		return True
	else :
		return False


def get_config():
	debug = False
	if len(sys.argv) > 1:
		fconfig = open(configFile, 'r')
		config_lines = fconfig.readlines()
		fconfig.close()
		configDic = {}
		for aline in config_lines:
			if not re.search("^ *#", aline) :
				config_args = aline.split('=')
				if "ovn_dir" in config_args[0]:
					configDic["ovn_dir"] = config_args[1].strip()
					os.system("chown -R root.tomcat %s" % configDic["ovn_dir"])
				elif "log_file" in config_args[0]:
					configDic["log"] = config_args[1].strip()
					os.system("chown -R root.tomcat %s" % configDic["log"])
				elif "listen_ip" in config_args[0]:
					configDic["listen_ip"] = config_args[1].strip()
				elif "listen_port" in config_args[0]:
					configDic["listen_port"] = int(config_args[1].strip())
				elif "debug" in config_args[0]:
					configDic["debug"] = str_to_bool(config_args[1].strip())
				elif "security" in config_args[0]:
					configDic["security"] = config_args[1].strip()
	
	else:
		configDic = {}
		configDic["ovn_dir"] = "/opt/virtualization/openkvi/"
		configDic["log"] = configDic["ovn_dir"]+"openkvi.log"
		configDic["listen_ip"] = '127.0.0.1'
		configDic["listen_port"] = 9999
		configDic["debug"] = True
	if not configDic.has_key("security"):
		configDic["security"] = "low"

	os.system("mkdir -p "+configDic["ovn_dir"])
	os.system("chmod -R 777 "+configDic["ovn_dir"])
	os.system('echo "" > '+configDic["log"])

	return configDic



### MAIN ###
global configFile
configFile = sys.argv[1]

global configDic
global eventListener
configDic = {}
configDic = get_config()
listen_ip = configDic["listen_ip"]
listen_port = configDic["listen_port"]
log_file = configDic["log"]
debug = configDic["debug"]


#if configDic["security"] == "low":
#	res = os.system("\cp -f /etc/nodemanager/nginx/openkvi_nginx_unsecure.conf /etc/nginx/conf.d/openkvi_nginx_default.conf")
#else:

res = os.system("\cp -f /etc/nodemanager/nginx/openkvi_nginx_secure.conf /etc/nginx/conf.d/openkvi_nginx_default.conf")
res = os.system("\cp -f /etc/nodemanager/nginx/openkvi_nginx_ssl.conf /etc/nginx/conf.d/openkvi_nginx_ssl.conf")
os.system("service nginx reload")


messenger = MSGControler(configDic)
messenger.log_info("<-- Service nodemanagerd has started. -->")

databaseAccess = PGSQLControler()
vmClass = VMSControler(messenger, databaseAccess)
eventListener = libvirtlistener.Listener(messenger, vmClass)
eventListener.startloop()
snapshot_handle = SnapshotControler(messenger, vmClass)
nodeClass = NodesControler(messenger, eventListener, vmClass, databaseAccess)
eventListener.nodeLib = nodeClass

try:
	server = SocketServer.ThreadingUDPServer((listen_ip, listen_port), handleConnection)
except:
	messengerf.log_error("Unable to bind UDP socket %s:%s !" % (listen_ip,listen_port))
	proc = subprocess.Popen(["ss", "-pantu"], stdout=subprocess.PIPE)
	code = proc.wait()
	for aline in proc.stdout:
		if (str(listen_ip)+':'+str(listen_port)) in aline and "UNCONN" in aline:
			tmpstr1 = re.sub(').*', '', re.sub('.*(', '', aline))
			pid = re.sub(',.*', '', re.sub('.*pid=', tmpstr1))
			prog = re.sub('.*"', '', re.sub('",.*', '', aline))
			self.log_warning("Process %s, PID %s, is binding port %s. It will be killed." % (prog, pid, listen_port))
			os.system("kill -9 %s" % pid)

	time.sleep(10)
	messenger.log_info("Trying again to bind %s on %s." % (listen_port, listen_ip))
	server = SocketServer.ThreadingUDPServer((listen_ip, listen_port), handleConnection)
	
server_thread = threading.Thread(target=server.serve_forever)
# Exit the server thread when the main thread terminates
server_thread.daemon = True
server_thread.start()

# We load nodes after UDP server init
# so OpenKVI can communicate with nodemanagerd
if nodeClass.load() < 0 :
        sys.exit(1)

max_count = 8  # number of sleeps before making a new try 
max_retry = 15 # X retry every 40s (8x5s) -> wait 10 minutes

in_count = 0
inactive_nodes = []
to_remove = []

try :
	while messenger.running:
		time.sleep(5)
		in_count += 1
		
		nodeClass.nlock.acquire_read()
		for aNode in nodeClass.nlist:
			if nodeClass.nlist[aNode]["state"] == "open":
				conn = nodeClass.nlist[aNode]["connection"]
				if conn.isAlive() != 1:
					inactive_nodes.append(aNode)
		
		nodeClass.nlock.release()
		
		if len(to_remove) > 0:
			to_remove = []
		
		for inactiveNode in inactive_nodes:
			if nodeClass.nlist.has_key(inactiveNode):
				if not nodeClass.nlist[inactiveNode].has_key("counter"):
					nodeClass.nlist[inactiveNode]["counter"] = 0
				
				nodeClass.nlock.acquire_read()
				state = nodeClass.nlist[inactiveNode]["state"]
				nodeClass.nlock.release()
				log = {}
				log["event"] = "NODE_STATUS"
				log["node"] = inactiveNode
				log["sender"] = "Node Manager"
				if state == "open":
					nodeClass.nlist[inactiveNode]["counter"] += 1
					messenger.log_info("%s is inactive !" % inactiveNode)
					log["status"] = "Warning"
					log["detail"] = "Node is unreachable"
					messenger.tell_all("EVENT", log)
					res = nodeClass.reconnect(inactiveNode)
					if res["state"]== "reconnected":
						log["status"] = "Connected"
						log["detail"] = "Node has been reconnected"
						messenger.print_debug("%s %s" % (inactiveNode, log["detail"]))
						messenger.tell_all("EVENT", log)
						to_remove.append(inactiveNode)
				
				elif in_count == max_count:
					nodeClass.nlist[inactiveNode]["counter"] += 1
					res = nodeClass.reconnect(inactiveNode)
					if res["state"] == "reconnected":
						log["status"] = "Connected"
						log["detail"] = "Node has been reconnected"
						messenger.print_debug("%s %s" % (inactiveNode, log["detail"]))
						messenger.tell_all("EVENT", log)
						to_remove.append(inactiveNode)
					
					elif nodeClass.nlist[inactiveNode]["counter"] == max_retry:
						log["status"] = "Error"
						log["detail"] = "Node seems to be down"
						messenger.log_error("%s : %s" % (inactiveNode, log["detail"]))
						messenger.tell_all("EVENT", log)
						to_remove.append(inactiveNode)
			else:
				to_remove.append(inactiveNode)
				
		for aNode in to_remove:
			inactive_nodes.remove(aNode)
		
		if in_count == max_count:
			in_count = 0
	
except:
	err = str(sys.exc_info()[1])
	print "Leaving nodemanager: "+err

## Shutdown tcp server ##
messenger.stop()

try:
	for aNode in nodeClass.nlist:
		if nodeClass.nlist[aNode]["webshell"].has_key("pids"):
			for pid in nodeClass.nlist[aNode]["webshell"]["pids"]:
				os.system("kill -9 %s" % pid)
except:
	err = str(sys.exc_info()[1])

messenger.log_info("<-- Service nodemanagerd has stopped. -->")
