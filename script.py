#!/usr/bin/env python

# This script enumerates SMTP users. It uses VRFY, EXPN, and RCPT TO methods.

import socket

class SMTPUserEnumerator():
	def __init__(self, target, userlist, port=25, scantype="vrfy", mailfrom="root"):
		# set init args as attributes
		self.target = target
		self.userlist = userlist
		self.port = port
		self.scantype = scantype
		self.mailfrom = [mailfrom, True] # boolean used for one-time sending of MAIL FROM command for RCPT scan

		self.sock = None # attribute for socket connected to target, generate with buildSock()
		self.targetBanner = None # banner from target server, stored upon vuln test

	def readUsers(self): # func to read file of usernames
		with open(self.userlist, 'r') as file:
			users = file.read().strip().split('\n') # read all, strip last newline, then split at every newline
		self.userlist = users # store list of usernames in self.userlist
		return

	def buildSock(self): # func to build socket
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.target, self.port)) # connect socket object to target
		self.sock = s # store socket object in self.sock
		banner = self.sock.recv(1024)[4::] # receive banner
		if self.targetBanner == None: # if we haven't already stored the banner
			self.targetBanner = banner # keep it
		return

	def closeSock(self): # func to close self.sock
		self.sock.close()
		self.sock = None
		return

	def testScanType(self): # func to test vulnerability to chosen scan
		if self.scantype == "vrfy": # VRFY scan
			self.sock.send("VRFY\n") # send empty VRFY command to target
			response = self.sock.recv(1024) # get response
			self.sock.send("QUIT\n") # quit SMTP
			self.closeSock() # shutdown socket
			if "501" in response: # if SMTP 501 syntax error
				return True # VRFY command is available
			else:
				return False
		elif self.scantype == "expn": # EXPN scan
			self.sock.send("EXPN\n") # send EXPN command
			response = self.sock.recv(1024)
			self.sock.send("QUIT\n")
			self.closeSock()
			if "502" in response: # if SMTP 502 command not recognized
				return False # EXPN is not available
			else:
				return True
		elif self.scantype == "rcpt": # RCPT TO scan
			self.sock.send("MAIL FROM:%s\n" %(self.mailfrom[0])) # send MAIL FROM command, use self.mailfrom for user
			self.sock.recv(1024)
			self.sock.send("RCPT TO:%s\n" %(self.mailfrom[0])) # send RCPT TO command, use self.mailfrom again
			response = self.sock.recv(1024)
			self.sock.send("QUIT\n")
			self.closeSock()
			if ("250" in response) or ("550" in response): # if RCPT TO is a recognized command (regardless if mailfrom user exists)
				return True # RCPT TO is available
			else:
				return False

	def vrfyProbe(self, user): # func to probe target with VRFY
		self.sock.send("VRFY %s\n" %(user)) # send VRFY command w/ username to target
		response = self.sock.recv(1024)
		if ("250" in response) or ("252" in response): # if 220 OK (or 252 because an unknown user returns 550)
			return True # user exists
		else:
			return False

	def expnProbe(self, user): # func to probe target with EXPN
		self.sock.send("EXPN %s\n" %(user)) # send EXPN command w/ username to target
		response = self.sock.recv(1024)
		if "250" in response: # if 250 OK
			return True # user exists
		else:
			return False

	def rcptProbe(self, user): # func to probe target with RCPT TO
		if self.mailfrom[1]: # if self.mailfrom[1] is True
			self.sock.send("MAIL FROM:%s\n" %(self.mailfrom[0])) # send MAIL FROM command w/ MAIL FROM username to target
			self.sock.recv(1024)
			self.mailfrom[1] = False # set self.mailfrom[1] to False (this MAIL FROM command will only be sent once)
		self.sock.send("RCPT TO:%s\n" %(user)) # send RCPT TO command w/ username
		response = self.sock.recv(1024)
		if "250" in response: # if 250 OK
			return True # user exists
		else:
			return False

	def probeTarget(self, user): # func to evaluate scan type and probe for a username accordingly
		if self.scantype == "vrfy":
			result = self.vrfyProbe(user)
		elif self.scantype == "expn":
			result = self.expnProbe(user)
		elif self.scantype == "rcpt":
			result = self.rcptProbe(user)
		return result

if __name__ == "__main__":
	import os
	import sys
	import argparse
	from datetime import datetime

	parser = argparse.ArgumentParser(description="SMTP User Enumeration Tool")
	parser.add_argument("-t", "--target", help="IP address of target SMTP server", action="store", dest="target", default=False)
	parser.add_argument("-p", "--port", help="Port number of target SMTP server (default: 25)", action="store", dest="port", default=25)
	parser.add_argument("-u", "--userlist", help="Path to wordlist of usernames to probe for", action="store", dest="file", default=False)
	parser.add_argument("--mailfrom", help="Change username used for MAIL FROM command (used in RCPT scan|default: root)", action="store", dest="user", default="root")
	parser.add_argument("--scan-vrfy", help="Use VRFY enumeration method", action="store_true", dest="vrfy", default=False)
	parser.add_argument("--scan-expn", help="Use EXPN enumeration method", action="store_true", dest="expn", default=False)
	parser.add_argument("--scan-rcpt", help="Use RCPT TO enumeration method", action="store_true", dest="rcpt", default=False)
	args = parser.parse_args()

	if len(sys.argv) == 1: # if no flags/switches are used
		parser.print_help() # print help page
		sys.exit(0) # exit

	if not args.target: # if no target given (default is False, not False == True)
		parser.error("No target IP address given") # raise parser error for no target IP address given
		sys.exit(1)
	try:
		socket.inet_aton(args.target) # attempt to run IP through socket.inet_aton
	except socket.error: # if there are any socket errors
		parser.error("Given target IP address is invalid") # the given IP is invalid
		sys.exit(1)

	try:
		if (int(args.port) < 1) or (int(args.port) > 65536): # convert args.port to integer and make sure it fits port range
			raise Exception # if it doesn't fit the port range, raise an exception
	except: # if an error is generated by the int conversion (a non-int being entered) or the range doesn't fit
		parser.error("Given target port number is invalid") # the port number is invalid
		sys.exit(1)

	if not args.file: # if no wordlist given
		parser.error("No wordlist given")
		sys.exit(1)
	elif not os.path.isfile(args.file): # if a wordlist was given but doesn't exist
		parser.error("Given wordlist does not exist")
		sys.exit(1)

	types = [args.vrfy, args.expn, args.rcpt] # put all scan-type values in a list for easier evaluation
	if (types.count(True) > 1) or (types.count(True) == 0): # if more than 1 True value OR if 0 True values
		parser.error("Scan type selection invalid (choose one)") # the scan choice is invalid
		sys.exit(1)

	# evaluate scan types in the order they were taken from args
	if types[0]: # args.vrfy is True
		scantype = "vrfy" # set scantype to vrfy
	elif types[1]:
		scantype = "expn"
	elif types[2]:
		scantype = "rcpt"

	print "[*] %s scan chosen for use against %s:%s" %(scantype.upper(), args.target, str(args.port)) # give info on scan back to user
	# create enumerator object and apply all validated input
	enumerator = SMTPUserEnumerator(args.target, args.file, port=int(args.port), scantype=scantype, mailfrom=args.user)

	print "[*] Checking for vulnerability to %s scan... " %(scantype.upper()),;sys.stdout.flush() # begin vuln check
	try:
		enumerator.buildSock() # build sock to target
		check = enumerator.testScanType() # call testScanType() and store result in check
		if check: # if testScanType() returned True
			print "[GOOD]" # target is vulnerable
		else: # if False is returned
			print "[BAD]" # target is not vulnerable
			sys.exit(1)
	except Exception: # if an error happens (bogus target info is entered)
		print "[FAIL]" # check failed
		sys.exit(1) # exit

	print "[*] Parsing list of users... ",;sys.stdout.flush() # tell user that file is being read
	try:
		enumerator.readUsers() # call readUsers() to read, parse, and store file contents
		print "[DONE]"
	except: # if something goes wrong
		print "[FAIL]" # fail out and exit
		sys.exit(1)

	print "[*] Trying %s users... \n" %(str(len(enumerator.userlist))) # print number of usernames to try
	startTime = datetime.now() # start clock for scan duration
	enumerator.buildSock() # call buildSock() to reconnect to target
	print "Target banner: %s" %(enumerator.targetBanner) # print target banner taken on vuln check
	for i in range(len(enumerator.userlist)): # enumerate through usernames
		result = enumerator.probeTarget(enumerator.userlist[i]) # call probeTarget() and pass current username
		if result: # if its a good username
			print "Found: %s" %(enumerator.userlist[i]) # report in console
	enumerator.closeSock() # close connection to target once scan is done
	stopTime = datetime.now() # stop clock for scan duration

	print "\n[*] Enumeration complete!" # complete scan
	print "[*] Duration: %s" %(str(stopTime-startTime)) # calculate and print scan duration
