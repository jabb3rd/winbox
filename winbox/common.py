#!/usr/bin/env python3

import struct
from socket import inet_aton
from binascii import hexlify, unhexlify

# Packet headers
M2_HEADER = b'M2'

# Indicates that the length takes one byte, thus the value is less than 2^8
SHORTLEN		= 0x01000000

# Different data formats
BOOL			= 0x00000000
U32			= 0x08000000
U64			= 0x10000000
ADDR6			= 0x18000000
STRING			= 0x20000000
MESSAGE			= 0x28000000
RAW			= 0x30000000

# Array type is a bitwise OR between a data type and ARRAY
ARRAY			= 0x80000000

# Different array types
BOOL_ARRAY		= ARRAY | BOOL
U32_ARRAY		= ARRAY | U32
U64_ARRAY		= ARRAY | U64
ADDR6_ARRAY		= ARRAY | ADDR6
STRING_ARRAY		= ARRAY | STRING
MESSAGE_ARRAY		= ARRAY | MESSAGE
RAW_ARRAY		= ARRAY | RAW

# Type/name filters are bitwise AND between a nametype and a corresponding filter
TYPE_FILTER		= 0xf8000000
NAME_FILTER		= 0x00ffffff
ARRAY_FILTER		= 0x7fffffff
BOOL_FILTER		= 0x01000000

# MT-style abbreviated notation
TYPE_REDUCTION = {
	BOOL:	 		'b',
	U32:	 		'u',
	U64:			'q',
	ADDR6:			'a',
	STRING:			's',
	MESSAGE:		'm',
	RAW:			'r',
	BOOL_ARRAY:		'B',
	U32_ARRAY:		'U',
	U64_ARRAY:		'Q',
	ADDR6_ARRAY:		'A',
	STRING_ARRAY:		'S',
	MESSAGE_ARRAY:		'M',
	RAW_ARRAY:		'R'
}

# Backward translation from an abbreviated notation
REDUCTION_TYPE = {
	'b':	BOOL,
	'u':	U32,
	'q':	U64,
	'a':	ADDR6,
	's':	STRING,
	'm':	MESSAGE,
	'r':	RAW,
	'B':	BOOL_ARRAY,
	'U':	U32_ARRAY,
	'Q':	U64_ARRAY,
	'A':	ADDR6_ARRAY,
	'S':	STRING_ARRAY,
	'M':	MESSAGE_ARRAY,
	'R':	RAW_ARRAY
}

# The size in bytes for the corresponing array elements
TYPE_SIZE = {
	BOOL:			1,
	U32:			4,
	U64:			8,
	ADDR6:			16,
	STRING:			0,
	MESSAGE:		0,
	RAW:			0,
}

# Message protocol constants
SYS_TO			= 0xff0001
SYS_FROM		= 0xff0002
SYS_TYPE		= 0xff0003
SYS_STATUS		= 0xff0004
SYS_REPLYEXP		= 0xff0005
SYS_REQID		= 0xff0006
SYS_CMD			= 0xff0007
SYS_ERRNO		= 0xff0008
SYS_ERRSTR		= 0xff0009
SYS_USER		= 0xff000a
SYS_POLICY		= 0xff000b
SYS_CTRL		= 0xff000d
SYS_CTRL_ARG		= 0xff000f
SYS_ORIGINATOR		= 0xff0012
SYS_RADDR6		= 0xff0013

CMD_GETPOLICIES		= 0xfe0001
CMD_GETOBJ		= 0xfe0002
CMD_SETOBJ		= 0xfe0003
CMD_GETALL		= 0xfe0004
CMD_NOTIFY		= 0xfe000b
CMD_GET			= 0xfe000d
CMD_SUBSCRIBE		= 0xfe0012

STD_ID			= 0xfe0001
STD_OBJS		= 0xfe0002
STD_GETALLID		= 0xfe0003
STD_GETALLNO		= 0xfe0004
STD_NEXTID		= 0xfe0005
STD_UNDOID		= 0xfe0006
STD_DYNAMIC		= 0xfe0007
STD_INACTIVE		= 0xfe0008
STD_DESCR		= 0xfe0009
STD_DISABLED		= 0xfe000a
STD_FINISHED		= 0xfe000b
STD_FILTER		= 0xfe000c
STD_DEAD		= 0xfe0013
STD_OBJ_COUNT		= 0xfe0019

TYPE_REQUEST		= 1
TYPE_REPLY		= 2

STATUS_OK		= 1
STATUS_ERROR		= 2

ERROR_UNKNOWN		= 0xfe0001
ERROR_UNKNOWNID		= 0xfe0004
ERROR_FAILED		= 0xfe0006
ERROR_EXISTS		= 0xfe0007
ERROR_NOTALLOWED	= 0xfe0009
ERROR_TOOBIG		= 0xfe000a
ERROR_BUSY		= 0xfe000c
ERROR_TIMEOUT		= 0xfe000d

def ip2dword(addr):
        return struct.unpack('<I', inet_aton(addr))[0]

def h(msg, data):
	print(msg, hexlify(data).decode())
