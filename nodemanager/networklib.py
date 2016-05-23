#!/usr/bin/python -u
""" 
Handle Node's network configuration 
"""

import sys
import threading
import subprocess
import os
import json
import xmltodict
import re
import ssh
import time

class NetworkControler:
	def __init__(self, node, connection, logger):
		self.nodeName = node
		self.connection = connection
		self.logger = logger
		self.netconfig = {}
		self.netconfig["ovs"] = {}
		self.netconfig["lbr"] = {}
		self.netconfig["virtualnet"] = {}
		self.physicalInterfaces = []
		self.getConfig()
	
	def ssh_command(self, command):
		""" Send ssh command to node """
		result, error = ssh.run(self.nodeName, command)
		if error:
			self.logger.log_error("Failed to send command %s to %s: %s" % (command, self.nodeName, str(sys.exc_info()[1])))
		return result, error
	
	def ssh_serial(self, cmd_list):
		""" Send ssh command to node """
		result, error = ssh.run_serial(self.nodeName, cmd_list)
		if error:
			self.logger.log_error("Failed to send serial commands to %s: %s" % (self.nodeName, str(sys.exc_info()[1])))
		return result, error
	
	def ssh_command_list(self, cmd_list):
		""" Send a list of ssh commands to node """
		result, error = ssh.run_list(self.nodeName, cmd_list)
		if error:
			self.logger.log_error("Failed to send command list %s to %s: %s" % (command, self.nodeName, str(sys.exc_info()[1])))
		return result, error
	
	def getConfig(self):
		"""Read Node's network settings"""
		ovs_cfg = {}
		self.netconfig["physicals"] = self.get_physicalInterfaces()
		self.netconfig["virtualnet"] = self.get_virtualNetworks()
		
		sshres, err = self.ssh_command('/bin/ls -l /var/run/openvswitch/db.sock')
		if err == "":
			ovs_cfg = self.ovs_show()
		else:
			ovs_cfg["error"] = "No openvswitch process"
		self.netconfig["ovs"] = ovs_cfg
		
		self.netconfig["lbr"] = self.brctl_show()
		return self.netconfig
	
	def updateBridgesInfo(self):
		""" Update self.netconfig["ovs"] and self.netconfig["lbr"] information
		"""
		sshres, err = self.ssh_command('/bin/ls -l /var/run/openvswitch/db.sock')
		if err == "":
			ovs_cfg = self.ovs_show()
		else:
			ovs_cfg["error"] = "No openvswitch process"
		self.netconfig["ovs"] = ovs_cfg
		
		self.netconfig["lbr"] = self.brctl_show()
	
	
	def get_physicalInterfaces(self):
		try:
			self.physicalInterfaces = []
			phy_cfg = {}
			phy_cfg["error"] = ""
			phy_cfg["ifaces"] = []
			cmd_list = []
			eth_list = []
			sriov_physical_functions = []
			sriov_virtual_functions = []
			
			# Search for SRIOV physical devices
			cmd_pf = {}
			cmd_pf["name"] = "sriov_pf"
			cmd_pf["command"] = 'find /sys/devices -name sriov_numvfs | sed -e "s|/sriov_numvfs||" | xargs -i -t ls {}/net 2>/dev/null'
			cmd_list.append(cmd_pf)
			# Search for SRIOV virtual functions
			cmd_vf = {}
			cmd_vf["name"] = "sriov_vf"
			cmd_vf["command"] = 'find /sys/devices -name physfn | sed -e "s|/physfn||" | xargs -i -t ls {}/net 2>/dev/null'
			cmd_list.append(cmd_vf)
			# Search for Network Devices
			cmd_dev = {}
			cmd_dev["name"] = "devices"
			cmd_dev["command"] = 'find /sys/devices -name net | grep -v "virtual" | xargs -i -t ls {}/ 2>/dev/null'
			cmd_list.append(cmd_dev)
			
			cmd_res, err = self.ssh_serial(cmd_list)
			sriov_physical_functions = cmd_res["sriov_pf"]["output"]
			sriov_virtual_functions = cmd_res["sriov_vf"]["output"]
			eth_list = []
			for eth in cmd_res["devices"]["output"]:
				if eth not in sriov_virtual_functions:
					eth_list.append(eth)
				
			
			cmd_list = []
			for eth_name in eth_list:
				cmd_bus = {}
				cmd_bus["name"] = eth_name+"_bus"
				cmd_bus["command"] = 'ls -l /sys/class/net/'+eth_name+'/device | sed -e "s/.*-> //" | sed -e "s/.*\///"'
				cmd_list.append(cmd_bus)
				
				cmd_subsystem = {}
				cmd_subsystem["name"] = eth_name+"_subsystem"
				cmd_subsystem["command"] = 'ls -l /sys/class/net/'+eth_name+'/device/ | grep "subsystem " | sed -e "s/.* -> //" | sed -e "s/.*\///"'
				cmd_list.append(cmd_subsystem)
				
				cmd_state = {}
				cmd_state["name"] = eth_name+"_state"
				cmd_state["command"] = 'cat /sys/class/net/'+eth_name+'/operstate'
				cmd_list.append(cmd_state)
				
				cmd_duplex = {}
				cmd_duplex["name"] = eth_name+"_duplex"
				cmd_duplex["command"] = 'cat /sys/class/net/'+eth_name+'/duplex 2>/dev/null'
				cmd_list.append(cmd_duplex)
				
				cmd_speed = {}
				cmd_speed["name"] = eth_name+"_speed"
				cmd_speed["command"] = 'cat /sys/class/net/'+eth_name+'/speed 2>/dev/null'
				cmd_list.append(cmd_speed)
				
				cmd_info = {}
				cmd_info["name"] = eth_name+"_info"
				cmd_tmp = 'lspci -s $'+eth_name+'_bus | sed -e "s/.*://" | sed -e "s/^ *//"'
				cmd_info["command"] = '[ $(echo $'+eth_name+'_subsystem | grep -v "usb") ] && '+cmd_tmp
				cmd_list.append(cmd_info)
				
			cmd_res, err = self.ssh_command_list(cmd_list)
			res = json.loads(cmd_res[0])
			self.logger.log_debug("json res : "+str(res))
			
			for eth in eth_list:
				new_eth = {}
				new_eth['name'] = eth
				new_eth['state'] = res[eth+"_state"]
				new_eth['duplex'] = res[eth+"_duplex"]
				new_eth['speed'] = res[eth+"_speed"]
				new_eth['info'] = res[eth+"_info"]
				new_eth['bus'] = res[eth+"_bus"]
				new_eth['subsystem'] = res[eth+"_subsystem"]
				if eth in sriov_physical_functions:
					cmd = 'find /sys/devices -name '+eth+' | sed -e "s|/net/'+eth+'||" | xargs -i -t cat {}/sriov_totalvfs'
					sshRes, err = self.ssh_command(cmd)
					for aline in sshRes:
						nb_vf = aline.strip()
					new_eth['sriov'] = nb_vf
				else:
					new_eth['sriov'] = '0'
				
				phy_cfg["ifaces"].append(new_eth)
				self.physicalInterfaces.append(eth)
		except:
			self.logger.log_error("Failed to get physicals devices: %s" % (str(sys.exc_info()[1])))
			print "Error: Failed to get physicals devices: %s" % (str(sys.exc_info()[1]))
		
		return phy_cfg
	
	def ovs_show(self):
		"""Get OVS configuration"""
		ovs_cfg = {}
		ovs_cfg["error"] = "None"
		ovs_cfg["bridges"] = []
		brlist = {}
		cmd = 'grep -i "^management *= *\\"*yes" /etc/sysconfig/network-scripts/ifcfg-* | sed -e "s/:.*//" | sed -e "s/.*ifcfg-//"'
		MNGT, err = self.ssh_command(cmd)
		sshRes, err = self.ssh_command('/usr/bin/ovs-vsctl show')
		if err != "":
			ovs_cfg["error"] = err
			return ovs_cfg
		else:
			brname = ""
			for aline in sshRes:
				aline = aline.strip()
				if 'Bridge' in aline:
					tmpargs = aline.split(" ")
					brname = tmpargs[1].strip('"')
					brlist[brname] = {}
					brlist[brname]["ports"] = []
					res, err = self.ssh_command('ip addr show ' +brname)
					for resline in res:
						if "inet " in resline:
							tmpstr1 = resline.strip().split(" brd")
							tmpstr2 = tmpstr1[0].split("inet ")
							brlist[brname]["inet"] = tmpstr2[1].strip()
				elif 'Port' in aline:
					tmpargs = aline.split(" ")
					portname = tmpargs[1].strip('"')
					if portname != brname:
						brlist[brname]["ports"].append(portname)
						brlist[brname][portname] = {}
						brlist[brname][portname]["ifaces"] = []
						res, err = self.ssh_command('ip addr show ' +portname)
						for resline in res:
							if "inet " in resline:
								tmpstr1 = resline.strip().split(" brd")
								tmpstr2 = tmpstr1[0].split("inet ")
								brlist[brname][portname]["inet"] = tmpstr2[1].strip()
				elif 'Interface' in aline:
					if portname != brname:
						tmpargs = aline.split(" ")
						inetname = tmpargs[1].strip('"')
						brlist[brname][portname]["ifaces"].append(inetname)
				elif 'tag:' in aline:
					if portname != brname:
						tmpargs = aline.split(":")
						tagnum = tmpargs[1].strip()
						brlist[brname][portname]["tag"] = tagnum
		
		for a_br in brlist.keys():
			new_br = {}
			new_br['name'] = a_br
			if a_br in MNGT:
				new_br['mngt'] = "yes"
			else:
				new_br['mngt'] = "no"
			if brlist[a_br].has_key("inet"):
				new_br['inet'] = brlist[a_br]["inet"]
			else:
				new_br['inet'] = "none"
			new_br['type'] = 'private'
			new_br['ports'] = []
			access = []
			for a_port in brlist[a_br]["ports"]:
				new_port = {}
				new_port['name'] = a_port
				new_port['ifaces'] = brlist[a_br][a_port]['ifaces']
				for an_iface in new_port['ifaces']:
					if an_iface in self.physicalInterfaces:
						new_br['type'] = 'public'
						access.append(a_port)
						break
				if brlist[a_br][a_port].has_key('tag'):
					new_port['tag'] = brlist[a_br][a_port]['tag']
				else:
					new_port['tag'] = '-1'
				
				if new_br['type'] == 'private' and a_port == a_br+"-nic":
					new_br['type'] = 'virtual'
				new_br['ports'].append(new_port)
				new_br['access'] = ', '.join(access)
			
			ovs_cfg['bridges'].append(new_br)
			
			
		sshRes, err = self.ssh_command('/usr/bin/ovs-appctl bond/list')
		ovs_cfg["bonds"] = [] 
		bondlist = {}
		if err != "":
			ovs_cfg["error"] = err
			return ovs_cfg
		elif len(sshRes) > 1:
			for aline in sshRes[1:]:
				aline = aline.strip()
				tmpargs = aline.split("\t")
				bondlist[tmpargs[0]] = {}
				bondlist[tmpargs[0]]["mode"] = tmpargs[1]
				bondlist[tmpargs[0]]["ifaces"] = []
				for inet in tmpargs[2].split(","):
					bondlist[tmpargs[0]]["ifaces"].append(inet.strip())
		
		for a_bond in bondlist.keys():
			new_bond = {}
			new_bond['name'] = a_bond
			new_bond['mode'] = bondlist[a_bond]['mode']
			new_bond['ifaces'] = bondlist[a_bond]['ifaces']
			ovs_cfg["bonds"].append(new_bond)
		
		return ovs_cfg
	
	def brctl_show(self):
		"""Get Linux bridges settings"""
		brctl_cfg = {}
		brctl_cfg["error"] = "None"
		brctl_cfg["bridges"] = []
		sshRes, err = self.ssh_command('/usr/sbin/brctl show 2>/dev/null')
		if err != "":
			brctl_cfg["error"] = err
			return brctl_cfg
		elif len(sshRes) > 1:
			brname = ""
			firstbr = True
			for aline in sshRes[1:]:
				if aline[0] != "":
					aline = aline.strip()
					tmpargs = aline.split("\t")
					brinfos = []
					for anarg in tmpargs:
						if len(anarg) > 0:
							brinfos.append(anarg)
					if len(brinfos) > 1:
						if not firstbr:
							brctl_cfg["bridges"].append(newbr)
						else:
							firstbr = False
						
						newbr = {}
						newbr["name"] = brinfos[0]
						newbr["ifaces"] = []
						if len(brinfos) > 3: 
							newbr["ifaces"].append(brinfos[3])
					elif len(brinfos) == 1:
						newbr["ifaces"].append(brinfos[0])
			brctl_cfg["bridges"].append(newbr)
		return brctl_cfg
	
	def get_virtualNetworks(self):
		"""
		Get Network defined on node
		"""
		try:
			virtnet_cfg = {}
			virtnet_cfg["error"] = ""
			network_list = self.connection.listNetworks()
			network_list_inactive = self.connection.listDefinedNetworks()
			network_list.extend(network_list_inactive)
			networks = []
			for aNet in network_list:
				net_infos = {}
				net_infos['name'] = aNet
				net_infos['type'] = ""
				pgroup = False
				
				network = self.connection.networkLookupByName(aNet)
				XMLDesc = network.XMLDesc(0)
				infos = xmltodict.parse(XMLDesc)['network']
				if infos.has_key('@connections'):
					net_infos['connections'] = infos['@connections']
				else:
					net_infos['connections'] = "0"
				
				if infos.has_key('forward') and infos['forward'].has_key('@mode'):
					net_infos['mode'] = infos['forward']['@mode']
					## Hanble SR-IOV devices
					if net_infos['mode'] == "hostdev":
						if infos['forward'].has_key('pf') and infos['forward']['pf'].has_key('@dev'):
							net_infos['sriov_dev'] = infos['forward']['pf']['@dev']
							pgroup = True
							net_infos['type'] = 'sriov'
						else:
							net_infos['sriov_dev'] = ""
				else:
					net_infos['mode'] = "private"
				
				net_infos['portgroups'] = []
				if infos.has_key('portgroup'):
					if isinstance(infos['portgroup'], list):
						for aGroup in infos['portgroup']:
							group_infos = {}
							group_infos['name'] = aGroup['@name']
							if aGroup.has_key('@default'):
								group_infos['is_default'] = aGroup['@default']
							else:
								group_infos['is_default'] = "no"
							if aGroup.has_key('vlan'):
								group_infos['vlan_id'] = aGroup['vlan']['tag']['@id']
							else:
								group_infos['vlan_id'] = "-1"
							net_infos['portgroups'].append(group_infos)
					else:
						group_infos = {}
						group_infos['name'] = infos['portgroup']['@name']
						if infos['portgroup'].has_key('@default'):
							group_infos['is_default'] = infos['portgroup']['@default']
						else:
							group_infos['is_default'] = "no"
						if infos['portgroup'].has_key('vlan'):
							group_infos['vlan_id'] = infos['portgroup']['vlan']['tag']['@id']
						else:
							group_infos['vlan_id'] = "-1"
						net_infos['portgroups'].append(group_infos)
				
				else:
					group_infos = {}
					group_infos['name'] = ""
					group_infos['is_default'] = "yes"
					if infos.has_key('vlan'):
						group_infos['vlan_id'] = infos['vlan']['tag']['@id']
					else:
						group_infos['vlan_id'] = "-1"
					net_infos['portgroups'].append(group_infos)
				
				if infos.has_key('bridge') and infos['bridge'].has_key('@name'):
					net_infos['bridge'] = infos['bridge']['@name']
					if net_infos['bridge'] == "private_"+net_infos['name']:
						net_infos['mode'] = "private"
				else:
					net_infos['bridge'] = ""
				
				if infos.has_key('virtualport') and infos['virtualport'].has_key('@type'):
					net_infos['type'] = infos['virtualport']['@type']
				
				net_infos['active'] = network.isActive()
				net_infos['persistent'] = network.isPersistent()
				networks.append(net_infos)
			
			virtnet_cfg["networks"] = networks
			
		except:
			self.logger.log_error("Failed to get %s networks: %s" % (self.nodeName, str(sys.exc_info()[1])))
			virtnet_cfg["error"] = "Error: cannot get %s networks: %s" % (self.nodeName, str(sys.exc_info()[1]))
		return virtnet_cfg
	
	def generate_network_xml(self, network):
		"""
		Create a Libvirt network
		INPUT:
		    network['name']       : Virtual Network's name
		    network['type']       : private/openvswitch/sriov
		    network['bridge']     : Either a bridge or a PF (if type = sriov)
		    network['portgroups'] : List of portgroups with :
		        portgroup['is_default']  : yes/no 
		        portgroup['name']        : Portgroup's name
				portgroup['vlan_id']     : VLAN tag
		"""
		result = ""
		try:
			self.logger.log_debug("creating virtual network %s" % network['name'])
			desc = '<network>'
			desc += '<name>'+network['name']+'</name>'
			if network['type'] == "private":
				desc += '<bridge name="private_'+network['name']+'" />'
				desc += '<forward mode="bridge" />'
				desc += '<virtualport type="openvswitch"/>'
				
			elif network['type'] == "openvswitch":
				src = network['bridge']
				desc += '<bridge name="'+src+'" />'
				desc += '<forward mode="bridge" />'
				desc += '<virtualport type="openvswitch"/>'
				
			elif network['type'] == "sriov":
				if network.has_key('sriov_dev'):
					src = network['sriov_dev']
				else:
					src = network['bridge']
				
				desc += '<forward mode="hostdev" managed="yes">'
				desc += '<pf dev="'+src+'"/>'
				desc += '</forward>'
				
			if network.has_key("portgroups"):
				for portgroup in network["portgroups"]:
					if portgroup['is_default'] == "yes":
						pdefault = 'default="yes" '
						if portgroup['name'] == "":
							pname = 'Default'
						else:
							pname = portgroup['name']
					else:
						pdefault = ''
						pname = portgroup['name']
					desc += '<portgroup name="'+pname+'" '+pdefault+'>'
					if portgroup['vlan_id'] != "-1":
						desc += '<vlan>'
						desc += '<tag id="'+portgroup['vlan_id']+'"/>'
						desc += '</vlan>'
					desc += '</portgroup>'
			desc += '</network>'
			result = desc
		
		except:
			self.logger.log_error("Failed to create network s: %s" % str(sys.exc_info()[1]))
			result = "Error: cannot generate network XML: %s" % str(sys.exc_info()[1])
			
		return result
	
	def create_virtualNetwork(self, data):
		"""
		Create a Libvirt network
		"""
		result = self._create_virtualNetwork(data)
		self.netconfig["virtualnet"] = self.get_virtualNetworks()
		return result
	
	def _create_virtualNetwork(self, data):
		result = "Success"
		try:
			network = json.loads(data)
			net_xml = self.generate_network_xml(network)
			if "Error: " in net_xml:
				return net_xml
			
			if network['type'] == "private":
				self.ovs_create_bridge("private_"+network['name'])
			
			for aVnet in self.netconfig["virtualnet"]['networks']:
				if aVnet['name'] == network['name']:
					self._remove_virtualNetwork(json.dumps(aVnet))
					break
			libvirt_network = self.connection.networkDefineXML(net_xml)
			libvirt_network.create()
			libvirt_network.setAutostart(1)
			
		except:
			self.logger.log_error("Failed to create network: %s" % str(sys.exc_info()[1]))
			result = "Error: cannot create network: %s" % str(sys.exc_info()[1])
		return result
	
	def update_virtualNetwork(self, data):
		"""
		Update a Libvirt network
		"""
		result = "Success"
		try:
			result = self._remove_virtualNetwork(data)
			result = self._create_virtualNetwork(data)
			self.netconfig["virtualnet"] = self.get_virtualNetworks()
			
		except:
			self.logger.log_error("Failed to create network s: %s" % str(sys.exc_info()[1]))
			result = "Error: cannot update network: %s" % str(sys.exc_info()[1])
		return result
	
	def remove_virtualNetwork(self, data):
		"""
		Remove a Libvirt network
		"""
		result = self._remove_virtualNetwork(data)
		self.netconfig["virtualnet"] = self.get_virtualNetworks()
		return result
	
	def _remove_virtualNetwork(self, data):
		try:
			
			network = json.loads(data)
			if network.has_key('old_name'):
				vswitch = network['old_name']
			else:
				vswitch = network['name']
			try:
				libvirt_network = self.connection.networkLookupByName(vswitch)
			except:
				return "Virtual Network %s not found !" % vswitch
			
			if network['type'] == "openvswitch" and network['mode'] == "private":
				self.ovs_remove_bridge("private_"+network['name'])
			
			if libvirt_network.isActive():
				libvirt_network.destroy()
			libvirt_network.undefine()
			del libvirt_network
			return "Success"
			
		except:
			self.logger.log_warning("Failed to remove network: %s" % str(sys.exc_info()[1]))
			return "Error: cannot remove: %s" % str(sys.exc_info()[1])
	
	def extend_vnic_infos(self, vnicList):
		"""
		Try to get on which interface each vnics are plugged
		INPUT: take a list of vnic info as input, each vnic is a dictionary containing:
			info['type']       : connexion type (network or bridge)
			info['vswitch']     : if type = network, then it is the name of the network else it's the bridge name
			info['portgroup']  : name of the portgroup (if empty then it's the default one)
			info['target']     : vnic name on the KVM server (eg vnet1, vnet2 ...) attched to the bridge
		
		OUTPUT: return the list of dictionary given in INPUT with, for each vnic, the additional below information:
			info['source']     : the name of the OVS or Linux bridge
			info['vlan_id']    : the vlan tag
			info['device_type] : "lbr" for a Linux Bridge, "ovs" for an OpenVswtich bridge
			info['state']      : state of the connection, either "up" or "down"
		
		"""
		try:
			result = {}
			result['error'] = ""
			result['vnics'] = []
			for vnic in vnicList:
				info = vnic
				brName = ""
				device_type = ""
				vlan_id = "-1"
				if info['type'] == "network":
					for aNetwork in self.netconfig['virtualnet']['networks']:
						if aNetwork['name'] == info['vswitch']:
							brName = aNetwork['bridge']
							device_type = aNetwork['type']
							for portgroup in aNetwork['portgroups']:
								if info['portgroup'] == "" and portgroup['is_default'] == "yes":
									vlan_id = portgroup['vlan_id']
									break
								elif info['portgroup'] == portgroup['name']:
									vlan_id = portgroup['vlan_id']
									break
									
							break
				elif info['type'] == "bridge":
					brName = info['vswitch']
					device_type = "lbr"
				
				state = "down"
				for aBridge in self.netconfig['ovs']['bridges']:
					if aBridge['name'] == brName:
						for aPort in aBridge['ports']:
							if aPort['name'] == info['target'] :
								if vlan_id == aPort['tag']:
									state = "up"
								else:
									state = "Error: wrong vlan"
								break
					else :
						for aPort in aBridge['ports']:
							if aPort['name'] == info['target'] :
								state = "Error: wrong vswitch"
								break
					
				if state == "down":
					for aBridge in self.netconfig['lbr']['bridges']:
						if aBridge['name'] == brName:
							if info['target'] in aBridge['ifaces'] :
								state = "up"
								break
				
				info['source'] = brName
				info['vlan_id'] = vlan_id
				info['device_type'] = device_type
				info['state'] = state
				result['vnics'].append(info)
			
		except:
			self.logger.log_warning("Failed to extend virtual interfaces infos: %s" % str(sys.exc_info()[1]))
			result['error'] = "Error: cannot extend virtual interfaces infos: %s" % str(sys.exc_info()[1])
		
		return result
	
	def update_vnic_connexion(self, source, dest):
		""" live update of a virtual network interface 
		PARAMS:
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
			brDestName = ""
			brSrcName = source['bridge']
			portgroup = dest['portgroup']
			vlan_id = "-1"
			vnet_type = ""
			if dest['type'] == "network":
				for aNetwork in self.netconfig['virtualnet']['networks']:
					if aNetwork['name'] == dest['vswitch']:
						vnet_type = aNetwork['type']
						brDestName = aNetwork['bridge']
						for aGroup in aNetwork['portgroups']:
							if portgroup == "":
								if aGroup['is_default'] == "yes":
									vlan_id = aGroup['vlan_id']
									break
							else:
								if aGroup['name'] == portgroup:
									vlan_id = aGroup['vlan_id']
									break
								
						break
			
			elif dest['type'] == "bridge":
				brDestName = dest['vswitch']
				vlan = '-1'
			
			if vnet_type != "sriov":
				if source['state'] != dest['state']:
					if dest['state'] == "down":
						res = self.detach_virtual_interface(source['vnic'], brSrcName)
					else:
						res = self.attach_virtual_interface(source['vnic'], brDestName, vlan_id)
				else:
					res = self.migrate_virtual_interface(source['vnic'], brSrcName, brDestName, vlan_id)
				self.updateBridgesInfo()
				result = res
			
			else :
				result = "Cannot do a live update of a SR-IOV device !"
			
		
		except:
			self.logger.log_warning("Failed to update virtual interface: %s" % str(sys.exc_info()[1]))
			result = "Error: cannot update virtual interface: %s" % str(sys.exc_info()[1])
		
		return result
	
	def attach_virtual_interface(self, vnic, bridge, vlan):
		""" Attach a virtual network interface to a bridge"""
		result = "Success"
		try:
			done = False
			for aBridge in self.netconfig['ovs']['bridges']:
				if aBridge['name'] == bridge:
					done = True
					if vlan == "-1":
						regexp = ".*--may-exist add-port "+bridge+" "+vnic+"."
						sshRes, err = self.ssh_command('/usr/bin/ovs-vsctl --may-exist add-port '+bridge+' '+vnic)
					else:
						regexp = ".*--may-exist add-port "+bridge+" "+vnic+" tag="+vlan+"."
						sshRes, err = self.ssh_command('/usr/bin/ovs-vsctl --may-exist add-port '+bridge+' '+vnic+' tag='+vlan)
					
					if err != "":
						str1 = re.sub(regexp, '', err)
						str2 = re.sub('^ but ', '' ,str1)
						result = "Failed to add port %s to OVS bridge %s: %s" % (vnic, bridge, str2)
						self.logger.log_warning(result)
					
					break
				
			if not done:
				for aBridge in self.netconfig['lbr']['bridges']:
					if aBridge['name'] == bridge:
						sshRes, err = self.ssh_command('/usr/sbin/brctl addif '+bridge+' '+vnic)
						if err != "":
							self.logger.log_warning("Failed to add port %s to LBR birdge %s: %s" % (vnic, bridge, err))
							result = "Error: "+err
						break
		
		except:
			self.logger.log_warning("Failed to attach virtual interface: %s" % str(sys.exc_info()[1]))
			result = "Error: cannot attach virtual interface: %s" % str(sys.exc_info()[1])
		
		return result
	
	def detach_virtual_interface(self, vnic, bridge):
		""" Attach a virtual network interface to a bridge"""
		result = "Success"
		try:
			done = False
			for aBridge in self.netconfig['ovs']['bridges']:
				if aBridge['name'] == bridge:
					done = True
					sshRes, err = self.ssh_command('/usr/bin/ovs-vsctl --if-exists del-port '+bridge+' '+vnic)
					if err != "":
						result = err
					break
			
			if not done:
				for aBridge in self.netconfig['lbr']['bridges']:
					if aBridge['name'] == bridge:
						sshRes, err = self.ssh_command('/usr/sbin/brctl delif '+bridge+' '+vnic)
						if err != "":
							result = err
						break
		
		except:
			self.logger.log_warning("Failed to detach virtual interface: %s" % str(sys.exc_info()[1]))
			result = "Error: cannot detach virtual interface: %s" % str(sys.exc_info()[1])
		return result
	
	def migrate_virtual_interface(self, vnic, src_bridge, dst_bridge, vlan):
		""" Attach a virtual network interface to a bridge"""
		result = ""
		try:
			self.detach_virtual_interface(vnic, src_bridge)
			result = self.attach_virtual_interface(vnic, dst_bridge, vlan)
		except:
			self.logger.log_warning("Failed to migrate virtual interface: %s" % str(sys.exc_info()[1]))
			result = "Error: cannot migrate virtual interface: %s" % str(sys.exc_info()[1])
		
		return result
	
	def ovs_create_bridge(self, bridge, interface=None):
		"""
		Create an OpenVswitch bridge
		INPUT:
			bridge     : OVS bridge name
			interface  : OVS egress interface, left empty for a private bridge
		"""
		result = "Success"
		try:
			br_conf = 'DEVICE='+bridge+'\n'
			br_conf += 'NM_CONTROLLED=no\n'
			br_conf += 'DEVICETYPE=ovs\n'
			br_conf += 'ONBOOT=yes\n' 
			br_conf += 'TYPE=OVSBridge\n'
			res, err = self.ssh_command('cat << EOF > /etc/sysconfig/network-scripts/ifcfg-'+bridge+'\n'+br_conf+'EOF')
			
			res, err = self.ssh_command('ovs-vsctl --if-exists del-br '+bridge)
			res, err = self.ssh_command('ovs-vsctl add-br '+bridge)
			
			if interface:
				self.ovs_add_exit_interface(bridge, interface)
			
			return result
		except:
			self.logger.log_error("Failed to create bridge: %s" % str(sys.exc_info()[1]))
			return "Error: cannot create bridge: %s" % str(sys.exc_info()[1])
	
	def ovs_remove_bridge(self, bridge):
		"""
		Remove an OVS network bridge
		"""
		try:
			res, err = self.ssh_command('rm -f /etc/sysconfig/network-scripts/ifcfg-'+bridge)
			res, err = self.ssh_command('ovs-vsctl --if-exists del-br '+bridge)
			return "done"
			
		except:
			self.logger.log_warning("Failed to remove bridge: %s" % str(sys.exc_info()[1]))
			return "Error: cannot remove bridge: %s" % str(sys.exc_info()[1])
	
	def ovs_add_exit_interface(self, bridge, interface):
		""" Add an exit (eth0, eth1, bond0 ...) NIC to an ovs bridge """
		try:
			print "ovs_add_exit_interface"
		except:
			self.logger.log_warning("Failed to add an exit interface to ovs bridge: %s" % str(sys.exc_info()[1]))
			return "Error: cannot add an exit interface to ovs bridge: %s" % str(sys.exc_info()[1])
	
	def create_bridge(self, config):
		"""
		Create a network bridge
		"""
		try:
			#config = json.loads(data)
			br_name = config["name"]
			br_conf = 'DEVICE='+br_name+'\n'
			br_conf += 'NM_CONTROLLED="yes"\n'
			br_conf += 'ONBOOT="yes"\n' 
			br_conf += 'TYPE="Bridge"\n'
			cmd = 'cat << EOF > /etc/sysconfig/network-scripts/ifcfg-'+br_name+'\n'+br_conf+'EOF'
			proc = subprocess.Popen(['ssh','-x','root@'+self.nodeName, cmd], stdout=subprocess.PIPE)
			code = proc.wait()
			cmd = 'ifup '+br_name
			proc = subprocess.Popen(['ssh','-x','root@'+self.nodeName, cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			code = proc.wait()
			if code != 0:
				return "Error: "+proc.stderr
			else:
				return "done"
			
		except:
			self.logger.log_error("Failed to create bridge: %s" % str(sys.exc_info()[1]))
			return "Error: cannot create bridge: %s" % str(sys.exc_info()[1])
	
	def remove_bridge(self, config):
		"""
		Remove a network bridge
		"""
		try:
			br_name = config["name"]
			cmd = 'ifdown '+br_name
			proc = subprocess.Popen(['ssh','-x','root@'+self.nodeName, cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			code = proc.wait()
			if code != 0:
				return "Error: "+proc.stderr
			else:
				cmd = 'rm -f /etc/sysconfig/network-scripts/ifcfg-'+br_name
				proc = subprocess.Popen(['ssh','-x','root@'+self.nodeName, cmd], stdout=subprocess.PIPE)
				code = proc.wait()
				return "done"
			
		except:
			self.logger.log_warning("Failed to remove bridge: %s" % str(sys.exc_info()[1]))
			return "Error: cannot remove bridge: %s" % str(sys.exc_info()[1])
	
	def find_vnet_ip(self, vnet, mac, ip_range):
		"""
		Find with arping2 a vnet's IP address
		"""
		try:
			list_ip = []
			arping_list = []
			range_info = ip_range.split(',')
			start_args = range_info[0].split('.')
			end_args = range_info[1].split('.')
			
			istart = int(start_args[3])
			iend = int(end_args[3])
			for i in range (istart,iend):
				if i == istart:
					ip_source = start_args[0]+"."+start_args[1]+"."+start_args[2]+"."+str(iend)
					ip_dest = start_args[0]+"."+start_args[1]+"."+start_args[2]+"."+str(i)
				else :
					ip_source = start_args[0]+"."+start_args[1]+"."+start_args[2]+"."+str(istart)
					ip_dest = start_args[0]+"."+start_args[1]+"."+start_args[2]+"."+str(i)
				arping_list.append('arping2 -c1 -p -S '+ip_source+' -i '+vnet+' '+mac+' -T '+ip_dest)
			
			cmd = 'tcpdump -Klanes0 -i '+vnet+' "ether host '+mac+'"'
			proc_tcpdump = subprocess.Popen(['ssh','-x','root@'+self.nodeName, cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			res = ssh.run_parallel(self.nodeName, arping_list)
			#time.sleep(2)
			proc_tcpdump.terminate()
			proc_tcpdump.wait()
			for line in proc_tcpdump.stdout:
				if "Request who-has" in line:
					str1 = re.sub('.* tell ', '' , line)
					res_ip = re.sub(',.*', '' , str1).strip()
					if res_ip not in list_ip:
						list_ip.append(res_ip)
			
			result = ', '.join(list_ip)
		except:
			self.logger.log_warning("Failed to find vnet IP address: %s" % str(sys.exc_info()[1]))
			return "Error: cannot find vnet IP address: %s" % str(sys.exc_info()[1])
		return result


if __name__ == '__main__':
	netControler = NetworkControler()
	config = netControler.read()	
	
