#!/usr/bin/env python3

import hashlib
from time import sleep
from winbox.common import *
from winbox.message import *
from winbox.packet import *
from winbox.tcpsession import *

# Winbox session with given data: host, port, user, password
class mtWinboxSession(object):
	def __init__(self, host, port):
		self.session = mtTCPSession(host, port)
		self.session.connect()
		self.session_id = None
		self.request_id = 0
		self.error = None

	# Close a session
	def close(self):
		self.session.close()
		self.session_id = None

	def request_list(self):
		self.request_id += 1
		msg = mtMessage()
		msg.set_to(2, 2)
		msg.set_from(0, 11)
		msg.set_command(7)
		msg.set_request_id(self.request_id)
		msg.set_reply_expected(True)
		msg.add_string(1, b'list')
		pkt = mtPacket(msg.build())

		self.session.send(pkt)
		sleep(0.2)
		reply = self.session.recv(1460)
		result = mtMessage(reply.raw)
		result.parse()

		error = result.get_value(SYS_ERRNO, U32)
		if error is not None:
			self.error = error
			return False

		session_id = result.get_value(STD_ID, U32)
		if session_id is not None:
			self.session_id = session_id
			return True
		else:
			raise Exception('Got no session id')
		return False

	# Request a challenge
	def request_challenge(self):
		if self.session_id is None:
			raise Exception('No session')

		self.request_id += 1

		msg = mtMessage()
		msg.set_session_id(self.session_id)
		msg.set_command(5)
		msg.set_from(0, 11)
		msg.set_to(2, 2)
		pkt1 = mtPacket(msg.build())
		self.session.send(pkt1)

		msg.clear()
		msg.set_reply_expected(True)
		msg.set_request_id(self.request_id)
		msg.set_command(4)
		msg.set_from(0, 11)
		msg.set_to(13, 4)
		pkt2 = mtPacket(msg.build())
		self.session.send(pkt2)

		reply = self.session.recv(1460)
		result = mtMessage(reply.raw)
		result.parse()
		return result.get_value(9, RAW)

	# MD5 challenge/response authentication
	def login(self, user, password):
		if self.session_id is not None:
			raise Exception('Already logged in')
		self.request_list()
		salt = self.request_challenge()
		digest = hashlib.md5()
		digest.update(b'\x00')
		digest.update(password)
		digest.update(salt)
		hashed = b'\x00' + digest.digest()

		self.request_id += 1
		msg = mtMessage()
		msg.set_to(13, 4)
		msg.set_from(0, 8)
		msg.set_command(1)
		msg.set_request_id(self.request_id)
		msg.set_session_id(self.session_id)
		msg.set_reply_expected(True)
		msg.add_string(1, user)
		msg.add_raw(9, salt)
		msg.add_raw(10, hashed)
		pkt = mtPacket(msg.build())
		self.session.send(pkt)
		reply = self.session.recv(1460)
		result = mtMessage(reply.raw)
		result.parse()

		error = result.get_value(SYS_ERRNO, U32)
		if error is not None:
			self.error = error
			return False
		return True

	# Dude-style cleartext login to a winbox server
	def login_cleartext(self, user, password):
		if self.session_id is not None:
			raise Exception('Already logged in')
		self.request_id += 1
		msg = mtMessage()
		msg.set_to(13, 4)
		msg.set_from(0, 8)
		msg.add_u32(7, 11)
		msg.add_u32(SYS_TYPE, 1)
		msg.set_request_id(self.request_id)
		msg.set_command(1)
		msg.add_string(1, user)
		msg.add_string(3, password)
		pkt = mtPacket(msg.build())

		self.session.send(pkt)
		reply = self.session.recv(1460)
		result = mtMessage(reply.raw)
		result.parse()

		error = result.get_value(SYS_ERRNO, U32)
		if error is not None:
			self.error = error
			return False

		session_id = result.get_value(STD_ID, U32)
		if session_id is not None:
			self.session_id = session_id
			return True
		return False
