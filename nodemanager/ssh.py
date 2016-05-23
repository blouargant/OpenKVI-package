#!/usr/bin/python -u
""" 
SSH library
"""

import sys
import subprocess
import os
import re
import threading

def run_old(target, command):
	""" Send ssh command to node """
	error = ""
	result = []
	try:
		proc = subprocess.Popen(['ssh','-x','root@'+target, command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		code = proc.wait()
		if code != 0:
			stderr = ''
			for aline in proc.stderr:
				stderr += aline+"\n" 
			error = stderr
		
		for aline in proc.stdout:
			result.append(aline.strip())
	except:
		error = "Error: cannot  send command %s to %s: %s" % (command, target, str(sys.exc_info()[1]))
	return result, error

def run(target, command, timeout=40, options=None):
	""" Send ssh command to node 
		The command is killed after "timeout" seconds
	"""
	error = ""
	result = []
	try:
		if options:
			CMD = ['ssh', options, '-x','root@'+target, command]
		else:
			CMD = ['ssh', '-x','root@'+target, command]
		proc = subprocess.Popen(CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		timer = threading.Timer(timeout, proc.kill)
		timer.start()
		code = proc.wait()
		timer.cancel()
		if code != 0:
			stderr = ''
			for aline in proc.stderr:
				stderr += aline+"\n" 
			error = stderr
		
		for aline in proc.stdout:
			result.append(aline.strip())
	except:
		error = "Error: cannot  send command %s to %s: %s" % (command, target, str(sys.exc_info()[1]))
	return result, error

def run_serial(target, cmd_list):
	""" Send ssh command to node """
	error = ""
	result = {}
	procs = {}
	try:
		for cmd in cmd_list:
			cmd_ref = cmd["name"]
			ssh_cmd = cmd["command"]
			procs[cmd_ref] = subprocess.Popen(['ssh','-x','root@'+target, ssh_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		
		for aref in procs.keys():
			result[aref] = {}
			code = procs[aref].wait()
			if code != 0:
				stderr = ''
				for aline in procs[aref].stderr:
					stderr += aline+"\n" 
				result[aref]['error'] = stderr
			result[aref]["output"] = []
			for aline in procs[aref].stdout:
				result[aref]["output"].append(aline.strip())
	except:
		error = "Error: cannot send serial commands to %s: %s" % (target, str(sys.exc_info()[1]))
		
	return result, error

def run_parallel(node, commands):
	""" 
	Run multiple SSH commands in parallel
	"""
	result = {}
	thread_lst = []
	try:
		def threadRunSSH(node, command, res):
			res, err = run(node, command)
		
		for cmd in commands:
			result[cmd] = []
			t = threading.Thread(target=threadRunSSH, args=(node, cmd, result[cmd]))
			thread_lst.append(t)
		for thread in thread_lst:
			thread.start()
		for thread in thread_lst:
			thread.join()
		
		result["error"] = ""
	except:
		self.logger.log_error("Failed run parallel SSH: %s" % str(sys.exc_info()[1]))
		result["error"] = "Error: cannot run parallel SSH: %s" % str(sys.exc_info()[1])
	return result

def run_list(target, cmd_list):
	""" Send a list of ssh commands to node """
	error = ""
	result = []
	tmp_list = []
	try:
		final_cmd = ""
		for aCmd in cmd_list:
			varname = aCmd["name"]
			varcmd = aCmd["command"]
			tmp_list.append("%s=$( %s ); " % (varname, varcmd))
		
		echo_line = ""
		for aCmd in cmd_list:
			varname = aCmd["name"]
			if echo_line == "":
				echo_line = '\\"'+varname+'\\": \\"$'+varname+'\\"'
			else:
				echo_line += ', \\"'+varname+'\\": \\"$'+varname+'\\"'
		
		tmp_list.append('echo "{'+echo_line+'}"')
		final_cmd = ''.join(tmp_list)
		proc = subprocess.Popen(['ssh','-x','root@'+target, final_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		code = proc.wait()
		if code != 0:
			stderr = ''
			for aline in proc.stderr:
				stderr += aline+"\n" 
			error = stderr
			
		for aline in proc.stdout:
			result.append(aline.strip())
	except:
		error = "Error: cannot  send command %s to %s: %s" % (command, target, str(sys.exc_info()[1]))
	return result, error
