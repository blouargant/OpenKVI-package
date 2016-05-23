#!/usr/bin/python -u
""" 
Handle Bash commands
"""

import sys
import subprocess
import os

def split_args(command):
	args = []
	tmpsplit = command.split(' "', 1)
	while len(tmpsplit) == 2:
		args.extend(tmpsplit[0].split(' '))
		remains = tmpsplit[1].split('" ', 1)
		if len(remains) != 2:
			tmpstr = remains[0]
			if not tmpstr[len(tmpstr)-1] == '"':
				raise Exception('Closing double cote not found !')
			else:
				finalstr = tmpstr.strip('"$')
				args.append(finalstr)
				return args
			
		args.append(remains[0])
		command = remains[1]
		tmpsplit = command.split(' "', 1)
		
	if len(command) > 0:
		args.extend(command.split(' '))
	return args

def run(command):
	""" Send bash command """
	result = ""
	errors = []
	FNULL = open(os.devnull, 'w')
	pipes = command.split(" | ")
	procs = []
	try:
		args = split_args(pipes[0].strip())
		procs.append(subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
		pipes.pop(0)
		i = 0
		for pipedCmd in pipes:
			args = split_args(pipedCmd.strip())
			procs.append(subprocess.Popen(args, stdin=procs[i].stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
			errors.append(procs[i].stderr.readline())
			procs[i].stdout.close()
			procs[i].stderr.close()
			i = i+1
		result , err = procs[len(procs)-1].communicate()
		errors.append(err)
	except:
		errors.append(str(sys.exc_info()[1]))
	return result, "\n".join(filter(None, errors))

def run_parallel(commands):
	"""
	Run multiple bash commands in parallel
	"""
	result = {}
	result["error"] = ""
	thread_lst = []
	try:
		def threadRunSSH(command, res):
			res, err = run(command)
			
		for cmd in commands:
			result[cmd] = []
			t = threading.Thread(target=threadRunSSH, args=(cmd, result[cmd]))
			thread_lst.append(t)
		for thread in thread_lst:
			thread.start()
		for thread in thread_lst:
			thread.join()
			
	except:
		result["error"] = "Error: cannot run parallel SSH: %s" % str(sys.exc_info()[1])
	
	return result

def background(command):
	""" Send bash command in background"""
	result = ""
	errors = []
	FNULL = open(os.devnull, 'w')
	pipes = command.split(" | ")
	procs = []
	try:
		args = split_args(pipes[0].strip())
		procs.append(subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
		pipes.pop(0)
		i = 0
		for pipedCmd in pipes:
			args = split_args(pipedCmd.strip())
			procs.append(subprocess.Popen(args, stdin=procs[i].stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
			errors.append(procs[i].stderr.readline())
			procs[i].stdout.close()
			procs[i].stderr.close()
			i = i+1
	except:
		errors.append(str(sys.exc_info()[1]))
		return "\n".join(filter(None, errors))
	
	return "running in background"
