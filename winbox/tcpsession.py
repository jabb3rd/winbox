#!/usr/bin/env python3

from socket import *
from winbox.common import *
from winbox.packet import *

# mtTCPSession to handle TCP winbox connections
class mtTCPSession(object):
	def __init__(self, host, port = None, timeout = None):
		self.host = host
		if port:
			self.port = port
		else:
			self.port = 8291
		if timeout:
			self.timeout = timeout
		else:
			self.timeout = 15
		self.ready = False

	# Connect to a winbox service
	def connect(self):
		try:
			self.socket = socket(AF_INET, SOCK_STREAM)
		except:
			raise Exception('Socket creation error!')
		if timeout:
			self.socket.settimeout(self.timeout)
		try:
			self.socket.connect((self.host, int(self.port)))
		except:
			self.ready = False
			raise Exception('Connection error to %s:%s' % (self.host, self.port))
		self.ready = True

	# Send arbitrary bytes
	def send_bytes(self, bytes):
		if not self.ready:
			raise Exception('Not connected to %s:%s' % (self.host, self.port))
		try:
			self.socket.sendall(bytes)
		except:
			return False
		return True

	# Receive arbitrary bytes
	def recv_bytes(self, size):
		if not self.ready:
			raise Exception('Not connected to %s:%s' % (self.host, self.port))
		result = self.socket.recv(size)
		return result

	# Close a connection
	def close(self):
		self.socket.close()
		self.ready = False

	# Send an mtPacket
	def send(self, msg):
		if not msg.header:
			msg.add_header()
		self.send_bytes(msg.raw)

	# Receive an mtPacket
	def recv(self, size):
		received_bytes = self.recv_bytes(size)
		if received_bytes is not None:
			result = mtPacket(received_bytes)
			result.remove_header()
		else:
			result = None
		return result
