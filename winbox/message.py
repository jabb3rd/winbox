#!/usr/bin/env python3

import struct
from io import BytesIO
from winbox.common import *

# mtMessage represents a Message protocol sequence
class mtMessage(object):
	def __init__(self, raw = None, parsed = False):
		self.contents = []
		self.raw = raw
		self.ready = False
		self.parsed = parsed

	# Clean up a bit, so the object can be reused again
	def clear(self):
		self.contents = []
		self.raw = None
		self.parsed = False

	# Add an arbitrary id/type/value to a sequence
	def add(self, id, type, value):
		self.contents.append((id, type, value))

	# Add a boolean
	def add_bool(self, id, value):
		self.add(id, BOOL, value)

	# Add an integer (u32)
	def add_u32(self, id, value):
		self.add(id, U32, value)

	# Add an array of u32 integers
	def add_u32_array(self, id, value):
		self.add(id, U32_ARRAY, value)

	# Add a long integer (u64)
	def add_u64(self, id, value):
		self.add(id, U64, value)

	# Add a string (a sequence of bytes, not a native python string)
	def add_string(self, id, value):
		self.add(id, STRING, value)

	# Add a raw data
	def add_raw(self, id, value):
		self.add(id, RAW, value)

	# Set a raw binary contents
	def set_raw(self, raw):
		self.raw = raw

	# Add a single M2 message
	def add_message(self, id, value):
		self.add(id, MESSAGE, value)

	# Add an array of M2 messages
	def add_message_array(self, id, value):
		self.add(id, MESSAGE_ARRAY, value)

	# Set a receiver, which will handle a request
	def set_to(self, handler, subhandler = None):
		if subhandler is None:
			self.add(SYS_TO, U32_ARRAY, [handler])
		else:
			self.add(SYS_TO, U32_ARRAY, [handler, subhandler])

	# Set a sender, which sends a request
	def set_from(self, handler, subhandler = None):
		if subhandler is None:
			self.add(SYS_FROM, U32_ARRAY, [handler])
		else:
			self.add(SYS_FROM, U32_ARRAY, [handler, subhandler])

	# Set a command to execute
	def set_command(self, command):
		self.add_u32(SYS_CMD, command)

	# Set a request ID
	def set_request_id(self, id):
		self.add_u32(SYS_REQID, id)

	# Set True to expect a reply after a request
	def set_reply_expected(self, value):
		self.add_bool(SYS_REPLYEXP, value)

	def set_session_id(self, id):
		self.add_u32(STD_ID, id)

	# Get a value of a given id/type
	def get_value(self, get_id, get_type):
		if not self.parsed:
			raise Exception('Not parsed yet')
		for k in self.contents:
			id, type, value = k
			if id == get_id and type == get_type:
				return value
		return None

	# Return True if there is a sequence with a given id/type (with any value)
	def has_value(self, id, type):
		if self.get_value(id, type) is not None:
			return True
		return False

	# Make a binary representation of a Message sequence
	def build(self):
		buffer = BytesIO()
		for k in self.contents:
			id, type, value = k
			typeid = id | type
			array = (typeid & ARRAY) >> 31
			if array:
				size = len(value)
				size_bytes = struct.pack('<H', size)
				elements_type = type & ARRAY_FILTER
				value_bytes = b''
				if elements_type == BOOL:
					for element in value:
						value_bytes += struct.pack('<B', element)
				elif elements_type == U32:
					for element in value:
						value_bytes += struct.pack('<I', element)
				elif elements_type == U64:
					for element in value:
						value_bytes += struct.pack('<Q', element)
				elif elements_type == MESSAGE:
					header_bytes = b''
					for element in value:
						element_bytes = element.build()
						element_size_bytes = struct.pack('<H', len(element_bytes) + 2)
						value_bytes += element_size_bytes + M2_HEADER + element_bytes
			if type == BOOL:
				size_bytes = b''
				value_bytes = b''
				typeid |= (value << 24)
			elif type == U32:
				size_bytes = b''
				if value < 256:
					typeid |= SHORTLEN
					value_bytes = struct.pack('<B', value)
				else:
					value_bytes = struct.pack('<I', value)
			elif type == U64:
				size_bytes = b''
				value_bytes = struct.pack('<Q', value)
			elif type == STRING or type == RAW:
				size = len(value)
				if size < 256:
					typeid |= SHORTLEN
					size_bytes = struct.pack('<B', size)
				else:
					size_bytes = struct.pack('<H', size)
				value_bytes = value
			# Needs to be checked
			elif type == MESSAGE:
				msg_bytes = value.build()
				size_bytes = struct.pack('<H', len(msg_bytes) + 2)
				value_bytes = M2_HEADER + msg_bytes
			typeid_bytes = struct.pack('<I', typeid)
			buffer.write(typeid_bytes + size_bytes + value_bytes)
		self.raw = buffer.getvalue()
		self.ready = True
		return self.raw

	# Dump a sequence (for debugging purposes)
	def dump(self):
		for i in self.contents:
			id, type, value = i
			if type == MESSAGE_ARRAY:
				print('%s%s:%s' % (TYPE_REDUCTION[type], hex(id)[2:], value))
				for m in value:
					for n in m:
						sub_id, sub_type, sub_value = n
						print('%s%s:%s' % (TYPE_REDUCTION[sub_type], hex(sub_id)[2:], sub_value))
					print()
			else:
				print('%s%s:%s' % (TYPE_REDUCTION[type], hex(id)[2:], value))

	# Make a Message sequence from a raw binary data
	def parse(self):
		if self.raw is None:
			raise Exception('No raw data')
		pointer = 0
		while pointer + 4 < len(self.raw):
			typeid, = struct.unpack('<I', self.raw[pointer:pointer+4])
			type = typeid & TYPE_FILTER
			id = typeid & NAME_FILTER
			short = (typeid & SHORTLEN) >> 24
			array = (typeid & ARRAY) >> 31
			pointer += 4
			if array:
				if short:
					array_length, = struct.unpack('<B', self.raw[pointer:pointer+1])
					pointer += 1
				else:
					array_length, = struct.unpack('<H', self.raw[pointer:pointer+2])
					pointer += 2
				element_type = typeid & ARRAY_FILTER
				i = 0
				array_contents = []
				elements_type = type & ARRAY_FILTER
				while i < array_length:
					if elements_type == BOOL:
						element_value, = struct.unpack('<B', self.raw[pointer:pointer+TYPE_SIZE[BOOL]])
						array_contents.append(element_value)
						pointer += TYPE_SIZE[BOOL]
					if elements_type == U32:
						element_value, = struct.unpack('<I', self.raw[pointer:pointer+TYPE_SIZE[U32]])
						array_contents.append(element_value)
						pointer += TYPE_SIZE[U32]
					# Treat M2 array as a raw data
					elif elements_type == MESSAGE:
						element_length, = struct.unpack('<H', self.raw[pointer:pointer+2])
						pointer += 2
						subheader = self.raw[pointer:pointer+2]
						if subheader != M2_HEADER:
							raise Exception('Not an M2 header in the array element')
						pointer += 2
						element_raw_value = self.raw[pointer:pointer+element_length-2]
						submessage = mtMessage(element_raw_value)
						submessage.parse()
						pointer += (element_length - 2)
						array_contents.append(submessage.contents)
					i += 1
				self.add(id, type, array_contents)
			else:
				if type == BOOL:
					value = (typeid & BOOL_FILTER) >> 24
					self.add(id, type, value)
				elif type == U32:
					if short:
						value, = struct.unpack('<B', self.raw[pointer:pointer+1])
						pointer += 1
					else:
						value, = struct.unpack('<I', self.raw[pointer:pointer+TYPE_SIZE[U32]])
						pointer += TYPE_SIZE[U32]
					self.add(id, type, value)
				elif type == U64:
					value, = struct.unpack('<Q', self.raw[pointer:pointer+TYPE_SIZE[U64]])
					pointer += TYPE_SIZE[U64]
					self.add(id, type, value)
				elif type == STRING:
					if short:
						string_length, = struct.unpack('<B', self.raw[pointer:pointer+1])
						pointer += 1
					else:
						string_length, = struct.unpack('<H', self.raw[pointer:pointer+2])
						pointer += 2
					value = self.raw[pointer:pointer+string_length]
					pointer += string_length
					self.add(id, type, value)
				elif type == RAW:
					if short:
						raw_length, = struct.unpack('<B', self.raw[pointer:pointer+1])
						pointer += 1
					else:
						raw_length, = struct.unpack('<H', self.raw[pointer:pointer+2])
						pointer += 2
					value = self.raw[pointer:pointer+raw_length]
					pointer += raw_length
					self.add(id, type, value)
				elif type == MESSAGE:
					message_length, = struct.unpack('<H', self.raw[pointer:pointer+2])
					pointer += 2
					subheader = self.raw[pointer:pointer+2]
					if subheader != M2_HEADER:
						raise Exception('Not an M2 header!')
					pointer += 2
					submessage = mtMessage(self.raw[pointer:pointer+message_length])
					pointer += message_length
					submessage.parse()
					self.add(it, type, submessage.contents)
				else:
					raise Exception('Typeid %s not implemented yet!' % hex(typeid))
		self.parsed = True
