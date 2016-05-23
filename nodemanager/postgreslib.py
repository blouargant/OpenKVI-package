#!/usr/bin/python -u
""" 
Handle postgresql database connection 
"""

import psycopg2
import sys
import os
from rwlock import RWLock

## TABLE nodes : 
#	id SERIAL PRIMARY KEY, 
#	name VARCHAR(50) NOT NULL, 
#	ip VARCHAR(50) NOT NULL, 
#	hypervisor VARCHAR(50) NOT NULL,
#	description VARCHAR(50));"

## TABLE vms : 
#	id SERIAL PRIMARY KEY,
#	memory INT,
#	nbcpu INT,
#	freqcpu VARCHAR(50),
#	arch VARCHAR(50),
#	network VARCHAR(50),
#	cdrom VARCHAR(50),
#	name VARCHAR(50) NOT NULL,
#	server VARCHAR(50) NOT NULL,
#	disks VARCHAR(50),
#	displayedname VARCHAR(50) NOT NULL);"


class PGSQLControler:
	
	def __init__(self):
		""" DB information """
		try:
			#self.db = database
			#self.user = user
			#self.password = password
			self.vmdb_lock = RWLock()
			self.nodedb_lock = RWLock()
			self.connection = psycopg2.connect(database='openkviDB', user='openkvi', password='openkvi')
			self.cursor = self.connection.cursor()
		except psycopg2.DatabaseError, e:
			print 'Error %s' % e
			sys.exit(1)
	
	def close(self):
		if self.connection:
			self.connection.close()
	
	def list_vms(self):
		result = {}
		result['status'] = "failed"
		result['vms'] = []
		self.vmdb_lock.acquire_read()
		try:
			self.cursor.execute('SELECT * FROM vms')
			rows = self.cursor.fetchall()
			for row in rows:
				vm ={}
				vm["memory"] = row[1]
				vm["nbcpu"] = row[2]
				vm["freqcpu"] = row[3]
				vm["arch"] = row[4]
				vm["network"] = row[5]
				vm["cdrom"] = row[6]
				vm["name"] = row[7]
				vm["server"] = row[8]
				vm["disks"] = row[9]
				vm["displayedname"] = row[10]
				result['vms'].append(vm)
			
			result['status'] = "successful"
			
		except psycopg2.DatabaseError, e:
			print 'Error %s' % e
		
		self.vmdb_lock.release()
		return result
	
	def list_nodes(self):
		result = {}
		result['status'] = "failed"
		result['nodes'] = []
		self.nodedb_lock.acquire_read()
		try:
			self.cursor.execute('SELECT * FROM nodes')
			rows = self.cursor.fetchall()
			for row in rows:
				node ={}
				node["name"] = row[1]
				node["ip"] = row[2]
				node["hypervisor"] = row[3]
				node["description"] = row[4]
				result['nodes'].append(node)
		
			result['status'] = "successful"
		
		except psycopg2.DatabaseError, e:
			print 'Error %s' % e
		
		self.nodedb_lock.release()
		return result
	
	def check_vm(self, vm, node):
		result = {}
		result['status'] = "failed"
		self.vmdb_lock.acquire_read()
		try:
			self.cursor.execute('SELECT * FROM vms WHERE name=%s AND WHERE server=%s', [vm, node])
			row = self.cursor.fetchone()
			result["name"] = row[7]
			result["node"] = row[8]
			result['status'] = "successful"
		
		except psycopg2.DatabaseError, e:
			print 'Error %s' % e
		
		self.vmdb_lock.release()
		return result
	
	def check_node(self, name):
		result = {}
		result['status'] = "failed"
		self.nodedb_lock.acquire_read()
		try:
			self.cursor.execute('SELECT * FROM nodes WHERE name=%s', [name])
			row = self.cursor.fetchone()
			result["name"] = row[1]
			result["ip"] = row[2]
			result["hypervisor"] = row[3]
			result["description"] = row[4]
			result['status'] = "successful"
		
		except psycopg2.DatabaseError, e:
			print 'Error %s' % e
		
		self.nodedb_lock.release()
		return result
	
	def add_node(self, name, ip, hypervisor, description ):
		result = "failed"
		self.nodedb_lock.acquire_write()
		try:
			# All CHAR entries are limited to 50 CHAR max
			in_name = name[0:49]
			in_ip = ip[0:49]
			in_hypervisor = hypervisor[0:49]
			in_description = description[0:49]
			SQL = "INSERT INTO nodes (name, ip, hypervisor, description) VALUES (%s, %s, %s, %s)"
			DATA = (in_name, in_ip, in_hypervisor, in_description)
			self.cursor.execute(SQL, DATA)
			self.connection.commit()
			result = "successful"
		
		except :
			print "POSTGRES ADD NODE error :"+str(sys.exc_info()[1])
		self.nodedb_lock.release()
		return result
	
	def remove_node(self, node):
		result = "failed"
		self.nodedb_lock.acquire_write()
		try:
			self.cursor.execute("DELETE FROM vms WHERE server=%s", [node])
			self.connection.commit()
			self.cursor.execute("DELETE FROM nodes WHERE name=%s", [node])
			self.connection.commit()
			result = "successful"
		
		except:
			print "POSTGRES REMOVE NODE error :"+str(sys.exc_info()[1])
		
		self.nodedb_lock.release()
		return result
	
	def add_vm(self, data):
		result = "Failed"
		# All CHAR entries are limited to 50 CHAR max
		self.vmdb_lock.acquire_write()
		try:
			iMem = int(data["memory"])
			iNbcpu = int(data["nbcpu"])
			freqcpu = data["freqcpu"][0:49]
			arch = data["arch"][0:49]
			network = data["network"][0:49]
			cdrom = data["cdrom"][0:49]
			name = data["name"][0:49]
			server = data["server"][0:49]
			disks = data["disks"][0:49]
			displayedname = data["displayedname"][0:49]
			SQL = "INSERT INTO vms (memory, nbcpu, freqcpu, arch, network, cdrom, name, server, disks, displayedname) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
			SQLDATA = (iMem, iNbcpu, freqcpu, arch, network, cdrom, name, server, disks, displayedname)
			self.cursor.execute(SQL, SQLDATA)
			self.connection.commit()
			result = "Successful"
		except:
			print "POSTGRES_ADD_VM error :"+str(sys.exc_info()[1])
			result = "Failed::"+str(sys.exc_info()[1])
		
		self.vmdb_lock.release()
		return result
	
	def update_vm(self, data):
		result = "Failed"
		# All CHAR entries are limited to 50 CHAR max
		iMem = int(data["memory"])
		iNbcpu = int(data["nbcpu"])
		network = data["network"][0:49]
		cdrom = data["cdrom"][0:49]
		name = data["name"][0:49]
		server = data["server"][0:49]
		disks = os.path.basename(data["disks"])[0:49]
		self.vmdb_lock.acquire_write()
		try:
			SQL = "UPDATE vms SET memory = %s, nbcpu = %s, network = %s, cdrom = %s, server = %s, disks = %s WHERE name = %s"
			SQLDATA = (iMem, iNbcpu, network, cdrom, server, disks, name)
			self.cursor.execute(SQL, SQLDATA)
			self.connection.commit()
			result = "Successful"
		except:
			print "POSTGRES_UPDATE_VM error :"+str(sys.exc_info()[1])
			result = "Failed::"+str(sys.exc_info()[1])
		
		self.vmdb_lock.release()
		return result
	
	def remove_vm(self, name, node):
		result = {}
		result['status'] = "failed"
		self.vmdb_lock.acquire_write()
		try:
			self.cursor.execute("DELETE FROM vms WHERE name=%s AND server=%s", (name, node))
			self.connection.commit()
			result['status'] = "successful"
		
		except:
			print "POSTGRES_REMOVE_VM error :"+str(sys.exc_info()[1])
		#except psycopg2.DatabaseError, e:
			#print 'Error %s' % e
		
		self.vmdb_lock.release()
		return result
	
	def change_vm_label(self, name, label):
		result = {}
		result['status'] = "failed"
		self.vmdb_lock.acquire_write()
		try:
			in_label = label[0:49]
			self.cursor.execute("UPDATE vms SET displayedname = %s WHERE name = %s", (in_label, name))
			self.connection.commit()
			result['status'] = "successful"
		
		except psycopg2.DatabaseError, e:
			print 'Error %s' % e
		
		self.vmdb_lock.release()
		return result
