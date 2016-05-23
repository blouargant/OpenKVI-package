#!/usr/bin/python -u
""" 
Handle Node's storage pools configuration
"""

import sys
import threading
import subprocess
import os
import json
import xmltodict
import re
import ssh

class StorageControler:
	def __init__(self, node, connection, logger):
		self.nodeName = node
		self.connection = connection
		self.logger = logger
		self.pools = []
		self.getPoolsConfig()
	
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
		return result
	
	def poolStateToString(self, state):
		stateStrings = ( "Inactive",
						"Building",
						"Running",
						"Degraded",
						"Inaccessible",
						"Unknown")
		return stateStrings[state]
	
	def virStorageVolType(self, type):
		volumeTypeToString = ( "File",
							"Block",
							"Directory",
							"Network",
							"Netdir",
							"Undefined")
		return volumeTypeToString[type]
	
	def getPoolsConfig(self):
		""" List defined storage pools on node """
		error = ""
		try:
			self.pools = []
			pool_list = self.connection.listStoragePools()
			if len(pool_list) == 0:
				xml = '<pool type="dir"><name>default_storage</name><target><path>/opt/virtualization/vmdisks/</path></target></pool>'
				self.connection.storagePoolDefineXML(xml, 0)
				pool = self.connection.storagePoolLookupByName("default_storage")
				pool.setAutostart(1)
				pool.create(0)
				del pool
				pool_list = self.connection.listStoragePools()
				
			for pool_name in pool_list:
				pool_config = {}
				pool = self.connection.storagePoolLookupByName(pool_name)
				xml_desc = pool.XMLDesc(0)
				pool_dict = xmltodict.parse(xml_desc)
				pool_config['type'] = pool_dict["pool"]["@type"]
				pool_config['path'] = pool_dict["pool"]["target"]["path"]
				pool_config['source'] = ""
				if pool_config['type'] == "fs":
					pool_config['source'] = pool_dict["pool"]["source"]["device"]["@path"]
				elif pool_config['type'] == "netfs":
					host = pool_dict["pool"]["source"]["host"]["@name"]
					path = pool_dict["pool"]["source"]["dir"]["@path"]
					netfs = pool_dict["pool"]["source"]["format"]["@type"]
					pool_config['source'] = netfs+"::"+host+":"+path
					
				info = pool.info()
				pool_config['name'] = pool_name
				pool_config['state'] = self.poolStateToString(info[0])
				pool_config['capacity'] = "%.2f" % (info[1] / 1048576 / 1024.0)
				pool_config['allocation'] = "%.2f" % (info[2] / 1048576 / 1024.0)
				pool_config['available'] = "%.2f" % (info[3] / 1048576 / 1024.0)
				
				#pool_config['volumes'] = []
				#volume_list = pool.listVolumes()
				#for vol_name in volume_list:
				#	vol_config = {}
				#	volume = pool.storageVolLookupByName(vol_name)
				#	vol_info = volume.info()
				#	vol_config['name'] = vol_name
				#	vol_config['type'] = self.virStorageVolType(vol_info[0])
				#	vol_config['capacity'] = "%.2f" % (vol_info[1] / 1048576 / 1024.0)
				#	vol_config['allocation'] = "%.2f" % (vol_info[2] / 1048576 / 1024.0)
				#	pool_config['volumes'].append(vol_config)
				
				self.pools.append(pool_config)
			
		except:
			self.logger.log_error("Failed to list storage pools: %s" % (str(sys.exc_info()[1])))
			error = "Error: Failed to list storage pools: %s" % (str(sys.exc_info()[1]))
			print error
		
		return self.pools, error
	
	def getVolumePathConfig(self, path):
		""" get volume info by path """
		error = ""
		result = {}
		result["format"] = ""
		result["vsize"] = "0"
		result["rsize"] = "0"
		result["error"] = ""
		try:
			cmd = "qemu-img info "+path
			res, err = self.ssh_command(cmd)
			if not err:
				result["format"] = res[1].split(":")[1].strip()
				vsize = re.sub('\(.*', '', res[2].split(":")[1])
				result["vsize"] = vsize.strip()
				result["rsize"] = res[3].split(":")[1].strip()
			else:
				result["error"] = err
				result["format"] = "not found"
			#volume = self.connection.storageVolLookupByPath(path)
		except:
			self.logger.log_error("Failed to get volume info by path: %s" % (str(sys.exc_info()[1])))
			error = "Error: Failed to get volume info by path: %s" % (str(sys.exc_info()[1]))
			result["error"] = error
		
		return result
