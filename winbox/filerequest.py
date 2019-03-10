#!/usr/bin/env python3

from io import BytesIO
from time import sleep
from winbox.common import *
from winbox.packet import *

# Requests a file from a device
class mtFileRequest(object):
	def __init__(self, winbox_session, filename):
		self.session = winbox_session.session
		self.session_id = None
		self.request_id = winbox_session.request_id
		self.filename = filename
		self.file_size = None
		self.fragment_size = 1460
		self.part_size = 32168
		self.buffer = BytesIO()
		self.error = None
		self.error_description = None

	# Get ready for a download and the necessary data such as file size and session id
	def request_download(self):
		self.request_id += 1
		msg = mtMessage()
		msg.set_reply_expected(True)
		msg.set_request_id(self.request_id)
		msg.set_command(3)
		msg.add_string(1, self.filename)
		msg.set_from(0, 8)
		msg.set_to(2, 2)
		pkt = mtPacket(msg.build())
		self.session.send(pkt)
		reply = self.session.recv(self.fragment_size)
		result = mtMessage(reply.raw)
		result.parse()

		self.error = result.get_value(SYS_ERRNO, U32)
		if self.error == ERROR_FAILED:
			self.error_description = result.get_value(SYS_ERRSTR, STRING)
			return False
		elif self.error is not None:
			return False
		self.session_id = result.get_value(STD_ID, U32)
		if self.session_id is None:
			raise Exception('Error getting download session id')
		self.file_size = result.get_value(2, U32)
		return True

	# Proceed with download, requesting a file chunk by chunk
	def download(self):
		if self.session_id is None:
			raise Exception('No session')
		if self.file_size is None:
			raise Exception('Haven\'t got a file size')
		file_done = False
		while not file_done:
			self.request_id += 1
			msg = mtMessage()
			msg.set_reply_expected(True)
			msg.set_request_id(self.request_id)
			msg.set_session_id(self.session_id)
			msg.add_u32(2, self.part_size)
			msg.set_command(4)
			msg.set_from(0, 8)
			msg.set_to(2, 2)
			pkt = mtPacket(msg.build())
			self.session.send(pkt)
			sleep(0.1)
			part_buffer = BytesIO()
			part_done = False
			while not part_done:
				data = self.session.recv_bytes(self.fragment_size)
				data_size = len(data)
				if data_size < self.fragment_size:
					part_done = True
				part_buffer.write(data)
			unpkt = mtPacket(part_buffer.getvalue())
			part_buffer.close()
			unpkt.remove_header()
			unmsg = mtMessage(unpkt.raw)
			unmsg.parse()
			part_data = unmsg.get_value(3, RAW)
			part_data_size = len(part_data)
			if part_data_size < self.part_size:
				file_done = True
			self.buffer.write(part_data)
		return self.buffer.getvalue()
