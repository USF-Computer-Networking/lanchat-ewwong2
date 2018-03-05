"""
Author: Edmund Wong
Resources:
	https://tutorialedge.net/python/udp-client-server-python/
	https://www.geeksforgeeks.org/simple-chat-room-using-python/
"""

import socket
import sys
from datetime import datetime
from scapy.all import srp,Ether,ARP,conf
import select
import argparse

def usage():
	print "Usage: python server.py <IP Address> <Port Number>"


def getValidIP():
	while True:
			IPAddress = raw_input("Enter IP Address: ")
			if IPAddress == "quit":
				exit()
			if isValidIP(IPAddress):
				break
	return IPAddress


def isValidIP(IPAddress):
	try:
	    socket.inet_aton(IPAddress)
	    return True
	except socket.error:
		print "Invalid IPv4 Address"
		return False


def getValidPort():
	while True:
			try:
				port = input("Enter Port: ")
				if port == -1:
					exit()
				elif port == 0:
					print "Invalid Port"
					continue
				else:
					break
			except NameError:
				print "Invalid Port"
				continue
	return port


def isValidPort(port):
	try:
		port = int(port)
		if port == 0:
			return False
		else:
			return True
	except ValueError:
		return False


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group()
	parser.add_argument("-IP", help="IP Address", default=None)
	parser.add_argument("-port", help="Port", default=None)
	group.add_argument("scan", help="turn on scan mode", action="store_true", default=False)
	group.add_argument("chat", help="turn on chat mode", action="store_true", default=False)
	args = parser.parse_args()

	if args.chat:
		argLen = len(sys.argv)
		if argLen == 1:
			IPAddress = getValidIP()
			port = getValidPort()
		elif args.IP is None or args.port is None:
			print "Both IP and Port must be given together"
			IPAddress = getValidIP()
			port = getValidPort()
		else:
			IPAddress = args.IP
			port = int(args.port)

		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			server.connect((IPAddress,port))
		except socket.error:
			print "Could not connect"
			exit()
		while True:
			socketList = [sys.stdin, server]
			read_sockets, write_sockets, error_socket = select.select(socketList, [], [])
			for socks in read_sockets:
				if socks == server:
					message = socks.recv(2048)
					print message
		        else:
		            message = sys.stdin.readline()
		            server.send(message)
		            if message == "exit\n":
		            	exit()
		            sys.stdout.write(IPAddress + " || ")
		            sys.stdout.write(message)
		            sys.stdout.flush()
	elif args.scan:
		try:
			interface = raw_input("Enter Desired Interface: ")
			IPAddress = getValidIP()
		except KeyboardInterrupt:
			print "Shutdown"
			exit(1)

		print "Scanning..."
    	start_time = datetime.now()
    	conf.verb = 0
    	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/AP(pdst = IPAddress), timeout = 2, iface=interface, inter=0.1)

    	print "MAC - IP\n"
    	for snd, rcv in ans:
    		print rcv.sprintf(r"%Ether.src% = %ARP.psrc%")
    	stop_time = datetime.now()
    	total_time = stop_time-start_time
    	print "\n Scan Complete"
    	print ("Scan Duration: %s" %(total_time))

try:
	server.close()
except socket.error:
	print ""