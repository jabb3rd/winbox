#!/usr/bin/env python3

import struct
from io import BytesIO
from winbox.common import *
from winbox.message import *

# This class represents a network packet
class mtPacket(object):
	def __init__(self, raw = None):
		self.raw = raw
		self.header = False

	def size(self):
		return len(self.raw)

	def clear(self):
		self.raw = None
		self.header = False

	# Returns True if a raw packet data contains a M2 header
	def has_header(self):
		if self.raw is None:
			raise Exception('No raw data in the packet yet')
		return self.raw[4:6] == M2_HEADER

	# Adds a M2 header for a raw data
	def add_header(self):
		if self.has_header():
			raise Exception('The raw data already has got a header')
		buffer = BytesIO()
		size = len(self.raw)
		# The contents is short (doesn't exceed 255 bytes)
		if size + 4 < 0xff:
			buffer.write(struct.pack('<B', size + 4) + b'\x01' + struct.pack('>H', size + 2) + M2_HEADER)
			buffer.write(self.raw)
		# The contents is long (so split it into several chunks up to 255 bytes)
		else:
			raw_headed = struct.pack('>H', size + 2) + M2_HEADER + self.raw
			first_chunk = True
			pointer = 0
			while pointer < size + 4:
				remaining = 4 + size - pointer
				if remaining > 0xff:
					remaining = 0xff
				if first_chunk:
					insertion = struct.pack('<BB', remaining, 0x01)
					first_chunk = False
				else:
					insertion = struct.pack('<BB', remaining, 0xff)
				buffer.write(insertion + raw_headed[pointer:pointer+remaining])
				pointer += remaining
		self.raw = buffer.getvalue()
		self.header = True
		return self.raw

	# Remove a M2 header
	def remove_header(self):
		if not self.has_header():
			raise Exception('Not an M2 packet')
		buffer = BytesIO()
		length, start, = struct.unpack('<BB', self.raw[0:2])
		if start != 0x01:
			raise Exception('Incorrect packet')
		if length < 0xff:
			buffer.write(self.raw[2:2+length])
		else:
			big_length, = struct.unpack('>H', self.raw[2:4])
			pointer = 0
			chunk_read_bytes = 0
			chunk = 0
			while pointer < len(self.raw):
				chunk += 1
				chunk_size, chunk_next = struct.unpack('<BB', self.raw[pointer:pointer+2])
				if chunk == 1:
					if chunk_next != 0x01:
						raise Exception('The first chunk is bad')
				else:
					if chunk_next != 0xff:
						raise Exception('Error in the chunk chain')
				pointer += 2
				buffer.write(self.raw[pointer:pointer+chunk_size])
				chunk_read_bytes += chunk_size
				pointer += chunk_size
		self.raw = buffer.getvalue()[4:]
		self.header = False
		buffer.close()
		return self.raw
