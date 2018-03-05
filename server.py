"""
Author: Edmund Wong
Resources:
	https://tutorialedge.net/python/udp-client-server-python/
	https://www.geeksforgeeks.org/simple-chat-room-using-python/
"""


import socket
import sys
import select
import argparse
from thread import *


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


def clientThread(conn, address):
	conn.send("""Welcome to this Chatroom!\nEnter 'exit' to leave chatroom""")
	while True:
		try:
			myMessage = conn.recv(2048)
			if myMessage=="exit\n":
				message = address[0] + " has left the chat room."
				broadcast(message, conn)
				remove(conn)
			if myMessage and myMessage != "exit":
				message = address[0] + " || " + myMessage
				broadcast(message, conn)
			else:
				message = address[0] + " has left the chat room."
				broadcast(message, conn)
				remove(conn)
		except:
			continue


# send to every client except itself
# if message cant be send to a client
# remove the client from the list
def broadcast(message, conn):
    for clients in clientList:
        if clients != conn:
            try:
                clients.send(message),
                clients.flush()
            except:
                clients.close()
                remove(clients)


def remove(conn):
    if conn in clientList:
        clientList.remove(conn)



# Set Up Global Variables
clientList=[]


if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument("-IP", help="IP Address", default=None)
	parser.add_argument("-port", help="Port", default=None)
	args = parser.parse_args()

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
		server.bind((IPAddress, port))
		print "Server connected"
	except socket.error:
		print "Server could not connect"
		exit()
	server.listen(20)

	while True:
		conn, address = server.accept()
		clientList.append(conn)
		message = address[0] + " joined."
		print message
		start_new_thread(clientThread,(conn, address))


conn.close()
server.close()

