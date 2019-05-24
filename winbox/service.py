#!/usr/bin/env python3

from winbox.common import *
from winbox.session import *

class mtServices(object):
	def __init__(self, winbox_session):
		self.session = winbox_session.session
		self.session_id = None
		self.request_id = winbox_session.request_id
		self.error = None
		self.error_description = None
		self.services = None

	def get_all(self):
		self.request_id += 1
		msg = mtMessage()
		msg.set_reply_expected(True)
		msg.set_request_id(self.request_id)
		msg.set_command(CMD_GETALL)
		msg.set_to(0x44, 0x01)
		msg.set_from(0x00, 0x57)
		pkt = mtPacket(msg.build())
		self.session.send(pkt)
		reply = self.session.recv(1000)
		result = mtMessage(reply.raw)
		result.parse()
		self.services = result.get_value(STD_OBJS, MESSAGE_ARRAY)

	def set_port(self, id, port):
		self.request_id += 1
		msg = mtMessage()
		msg.set_reply_expected(True)
		msg.set_request_id(self.request_id)
		msg.set_command(CMD_SETOBJ)
		msg.set_to(0x44, 0x01)
		msg.set_from(0x00, 0x57)
		msg.add_u32(2, port)
		msg.add_u32(STD_ID, id)
		pkt = mtPacket(msg.build())
		self.session.send(pkt)
		reply = self.session.recv(1000)
		result = mtMessage(reply.raw)
		result.parse()

	def set_disabled(self, id, disabled):
		self.request_id += 1
		msg = mtMessage()
		msg.set_reply_expected(True)
		msg.set_request_id(self.request_id)
		msg.set_command(CMD_SETOBJ)
		msg.set_to(0x44, 0x01)
		msg.set_from(0x00, 0x57)
		msg.add_bool(STD_DISABLED, disabled)
		msg.add_u32(STD_ID, id)
		pkt = mtPacket(msg.build())
		self.session.send(pkt)
		reply = self.session.recv(1000)
		result = mtMessage(reply.raw)
		result.parse()

	def get_id(self, name):
		for s in self.services:
			service_id = None
			service_name = None
			for id, type, value in s:
				if id == STD_ID and type == U32:
					service_id = value
				if id == 1 and type == STRING:
					service_name = value
			if service_name == name:
				return service_id
		return None

	def get_data(self, service_id):
		for s in self.services:
			for id, type, value in s:
				if id == STD_ID and type == U32:
					if value == service_id:
						return s
		return None

	def get_value(self, service, param_id, param_type):
		for id, type, value in service:
			if id == param_id and type == param_type:
				return value
		return None

