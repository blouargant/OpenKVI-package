#!/usr/bin/python -u
"""
RSYNC library
"""

import os
import subprocess
import re

RSYNC = ["rsync", "-a", "--delete", "--exclude", "tmp", "--exclude", "TMP"]

def send(src, dst, remote):
	"""
	Send a file to remote server using rsync over ssh
	SSH keys must have been exchanged before
	src: local source file or directory
	dst: remote destination directory
	remote: remoste server
	"""
	err = ""
	try:
		if dst[len(dst)-1] != "/":
			return "Error: remote destination must be a directory"
		
		cmd = []
		cmd.extend(RSYNC)
		rdest = "root@%s:%s" % (remote, dst)
		cmd.extend([src, rdest])
		proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		code = proc.wait()
		if code != 0:
			err = ' '.join(proc.stderr)
		
	except:
		err = "Error: cannot send file %s to %s: %s" % (src, node, str(sys.exc_info()[1]))
	return err


def get(src, dst, remote):
	"""
	get a file from a remote server using rsync over ssh
	SSH keys must have been exchanged before
	src: remote source file or directory
	dst: local destination directory
	remote: remoste server
	"""
	err = ""
	try:
		if dst[len(dst)-1] != "/":
			return "Error: local destination must be a directory"
		
		cmd = []
		cmd.extend(RSYNC)
		rsrc = "root@%s:%s" % (remote, src)
		cmd.extend([rsrc, dst])
		proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		code = proc.wait()
		if code != 0:
			err = ' '.join(proc.stderr)
		
	except:
		err = "Error: cannot send file %s to %s: %s" % (src, node, str(sys.exc_info()[1]))
	return err
