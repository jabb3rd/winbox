#!/usr/bin/env python3

from winbox.common import *
from winbox.tcpsession import *
from winbox.message import *
from winbox.packet import *

# Implements some of the /nova/bin/agent probes
class mtAgent(object):
	# Connect to the agent
	def __init__(self, host, port):
		self.request_id = 0
		self.error = None
		self.error_description = None
		self.session = mtTCPSession(host, port)
		self.session.connect()
		self.result = None

	def clear_error(self):
		self.error = None
		self.error_description = None
		self.result = None

	def do_probe(self, msg):
		self.clear_error()
		pkt = mtPacket(msg.build())
		self.session.send(pkt)
		reply = self.session.recv(1024)
		self.result = mtMessage(reply.raw)
		self.result.parse()
		error = self.result.get_value(SYS_ERRNO, U32)
		if error is not None:
			self.error = error
			error_description = self.result.get_value(SYS_ERRSTR, STRING)
			if error_description is not None:
				self.error_description = error_description
			return False
		elif self.result.get_value(13, BOOL):
			return True

	def tcp_probe(self, host, port, send, receive):
		self.request_id += 1
		msg = mtMessage()
		msg.set_to(0x68)
		msg.set_command(1)
		msg.set_request_id(self.request_id)
		msg.set_reply_expected(True)
		msg.add_int(3, ip2dword(host))
		msg.add_int(4, port)
		if send != b'':
			msg.add_string(7, send)
		if receive != b'':
			msg.add_string(8, receive)
		return self.do_probe(msg)

	def udp_probe(self, host, port, send, receive):
		self.request_id += 1
		msg = mtMessage()
		msg.set_to(0x68)
		msg.set_command(2)
		msg.set_request_id(self.request_id)
		msg.set_reply_expected(True)
		msg.add_int(3, ip2dword(host))
		msg.add_int(4, port)
		if send != b'':
			msg.add_string(7, send)
		if receive != b'':
			msg.add_string(8, receive)
		return self.do_probe(msg)

	def netbios_probe(self, host):
		self.request_id += 1
		msg = mtMessage()
		msg.set_to(0x68)
		msg.set_command(3)
		msg.set_request_id(self.request_id)
		msg.set_reply_expected(True)
		msg.add_int(3, ip2dword(host))
		return self.do_probe(msg)
