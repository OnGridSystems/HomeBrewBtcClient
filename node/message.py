import binascii
import hashlib
import random
import socket
import struct
import time

import node.settings as settings
from node.bloom import BloomFilter

# The object type is currently defined as one of the following possibilities:
# Value 	Name 	            Description
# 0 	    ERROR   	        Any data of with this number may be ignored
# 1 	    MSG_TX 	            Hash is related to a transaction
# 2 	    MSG_BLOCK 	        Hash is related to a data block
# 3 	    MSG_FILTERED_BLOCK 	Hash of a block header; identical to MSG_BLOCK. Only to be used in getdata message.
#                               Indicates the reply should be a merkleblock message rather than a block message; this
#                               only works if a bloom filter has been set.
# 4 	    MSG_CMPCT_BLOCK 	Hash of a block header; identical to MSG_BLOCK. Only to be used in getdata message.
#                               Indicates the reply should be a cmpctblock message. See BIP 152 for more info.
ERROR = 0
MSG_TX = 1
MSG_BLOCK = 2
MSG_FILTERED_BLOCK = 3
MSG_CMPCT_BLOCK = 4


# MESSAGES https://en.bitcoin.it/wiki/Protocol_documentation
# version
# verack
# addr
# inv
# getdata
# notfound
# getblocks
# getheaders
# tx
# block
# headers
# getaddr
# mempool
# checkorder
# submitorder
# reply
# ping
# pong
# reject # All implementations of the P2P protocol version 70,002 and later should support the reject message.

# These messages are related to Bloom filtering of connections and are defined in BIP 0037:
# filterload BIP37
# filteradd BIP37
# filterclear BIP37
# merkleblock BIP37

# alert
# sendheaders BIP130 version >= 70012 or Bitcoin Core version >= 0.12.0.
# feefilter BIP133 version >= 70013
# sendcmpct BIP152 version >= 70014
# cmpctblock BIP152 version >= 70014
# getblocktxn BIP152 version >= 70014


# Number of bytes in payload. The current maximum number of bytes (MAX_SIZE) allowed in the payload by Bitcoin Core
# is 32 MiB—messages with a payload size larger than this will be dropped or rejected.
def make(command, payload, magic=settings.MAGIC):
    if len(payload) > 1024 * 1024 * 32:
        raise ValueError('PAYLOAD IS LARGER THAN 32MB')
    checksum = get_checksum(payload)
    return magic + struct.pack('<12sL4s',
                               bytes(command.encode('utf-8')),
                               len(payload),
                               checksum) + payload


# Payload:
# Field Size 	Description 	Data type 	Comments
# 4 	        version 	    int32_t 	Identifies protocol version being used by the node
# 8 	        services 	    uint64_t 	bitfield of features to be enabled for this connection
# 8 	        timestamp 	    int64_t 	standard UNIX timestamp in seconds
# 26 	        addr_recv 	    net_addr 	The network address of the node receiving this message
# Fields below require version ≥ 106
# 26 	        addr_from 	    net_addr 	The network address of the node emitting this message
# 8 	        nonce 	        uint64_t 	Node random nonce, randomly generated every time a version packet is sent.
#                                           This nonce is used to detect connections to self.
#  ? 	        user_agent 	    var_str 	User Agent (0x00 if string is 0 bytes long)
# 4 	        start_height 	int32_t 	The last block received by the emitting node
# Fields below require version ≥ 70001
# 1 	        relay 	        bool 	Whether the remote peer should announce relayed transactions or not, see BIP 0037
def get_version(version=settings.VERSION, services=0, addr_recv=['127.0.0.1', 18333],
                addr_from=['127.0.0.1', 18333], user_agent='', start_height=0, relay=True):
    payload = struct.pack('<L', version)
    payload += struct.pack('<Q', services)
    payload += struct.pack('<Q', int(time.time()))

    addr_recv = net_address(services, addr_recv[0], addr_recv[1])
    addr_from = net_address(services, addr_from[0], addr_from[1])

    payload += struct.pack('<26s', addr_recv)
    payload += struct.pack('<26s', addr_from)
    nonce = random.getrandbits(64)
    payload += struct.pack('<Q', nonce)

    user_agent = get_var_str(user_agent)

    payload += user_agent
    payload += struct.pack('<L', start_height)

    # Relay
    # If false then broadcast transactions will not be announced until a filter{load,add,clear} command is received.
    # If missing or true, no change in protocol behaviour occurs.
    if version >= 70001:
        payload += struct.pack('B', relay)

    return make('version', payload)


# Message header:
#  F9 BE B4 D9                          - Main network magic bytes
#  76 65 72 61  63 6B 00 00 00 00 00 00 - "verack" command
#  00 00 00 00                          - Payload is 0 bytes long
#  5D F6 E0 E2                          - Checksum
def get_verack():
    checksum = get_checksum(b'')
    return make('verack', checksum)


# Field Size 	Description 	Data type 	                Comments
# 1+ 	        count 	        var_int 	                Number of address entries (max: 1000)
# 30x? 	        addr_list 	    (uint32_t + net_addr)[] 	Address of other nodes on the network. version < 209 will
#                                                           only read the first one. The uint32_t is a timestamp.
# Note: Starting version 31402, addresses are prefixed with a timestamp. If no timestamp is present, the addresses
# should not be relayed to other peers, unless it is indeed confirmed they are up.
def get_addr():
    raise NotImplemented


# Payload (maximum 50,000 entries, which is just over 1.8 megabytes):
# Field Size 	Description 	Data type 	Comments
#  ? 	        count 	        var_int 	Number of inventory entries
# 36x? 	        inventory 	    inv_vect[] 	Inventory vectors
def get_inv(vectors):
    payload = b''
    if len(vectors) > 50000:
        raise ValueError('To many vectors')
    payload += get_var_int(len(vectors))
    for v in vectors:
        payload += struct.pack('<L32c', v[0], v[1])

    return make('inv', payload)


# Payload (maximum 50,000 entries, which is just over 1.8 megabytes):
# Field Size 	Description 	Data type 	Comments
#  ? 	        count 	        var_int 	Number of inventory entries
# 36x? 	        inventory 	    inv_vect[] 	Inventory vectors
def get_getdata(vectors):
    payload = b''
    if len(vectors) > 50000:
        raise ValueError('To many vectors')
    payload += get_var_int(len(vectors))
    for v in vectors:
        payload += struct.pack('<L', v[0]) + binascii.unhexlify(v[1])[::-1]
    return make('getdata', payload)


# Field Size 	Description 	Data type 	Comments
#  ? 	        count 	        var_int 	Number of inventory entries
# 36x? 	        inventory 	    inv_vect[] 	Inventory vectors
def get_notfound():
    raise NotImplemented


# Field Size 	Description 	        Data type 	Comments
# 4 	        version 	            uint32_t 	the protocol version
# 1+ 	        hash count 	            var_int 	number of block locator hash entries
# 32+ 	        block locator hashes 	char[32] 	block locator object; newest back to genesis block (dense to start,
#                                                   but then sparse)
# 32 	        hash_stop 	            char[32] 	hash of the last desired block; set to zero to get as many blocks
#                                                   as possible (500)
def get_getblocks(locator, version=settings.VERSION):
    payload = struct.pack('<L', version)
    # locator is list
    hash_count = len(locator)
    hash_count = get_var_int(hash_count)
    payload += hash_count
    for loc_hash in locator:
        payload += binascii.unhexlify(loc_hash)[::-1]
    payload += b'\x00' * 32
    return make('getblocks', payload)


# Field Size 	Description 	        Data type 	Comments
# 4 	        version 	            uint32_t 	the protocol version
# 1+ 	        hash count 	            var_int 	number of block locator hash entries
# 32+ 	        block locator hashes 	char[32] 	block locator object; newest back to genesis block
#                                                   (dense to start, but then sparse)
# 32 	        hash_stop 	            char[32] 	hash of the last desired block header; set to zero to get as many
#                                                   blocks as possible (2000)
def get_getheaders(hashes, version=settings.VERSION, stop_hash=b'\x00' * 32):
    hash_count = len(hashes)
    hash_count = get_var_int(hash_count)
    payload = struct.pack('<L', version)
    payload += hash_count
    for block_hash in hashes:
        payload += binascii.unhexlify(block_hash)[::-1]
    payload += binascii.unhexlify(stop_hash)[::-1]
    return make('getheaders', payload)


def get_tx():
    raise NotImplemented


def get_block():
    raise NotImplemented


# Field Size 	Description 	        Data type 	Comments
# 4 	        version 	            uint32_t 	the protocol version
# 1+ 	        hash count 	            var_int 	number of block locator hash entries
# 32+ 	        block locator hashes 	char[32] 	block locator object; newest back to genesis block (dense to start,
#                                                   but then sparse)
# 32 	        hash_stop 	            char[32] 	hash of the last desired block header; set to zero to get as many
#                                                   blocks as possible (2000)
def get_headers(locator, version=settings.VERSION, hash_stop=b'\x00' * 32):
    payload = struct.pack('<L', version)
    payload += get_var_int(len(locator))
    for loc_hash in locator:
        payload += binascii.unhexlify(loc_hash)[::-1]
    payload += hash_stop
    return make('getheaders', payload)


def get_getaddr():
    raise NotImplemented


# BIP35
def get_mempool():
    return make('mempool', b'')


def get_checkorder():
    raise NotImplemented


def get_submitorder():
    raise NotImplemented


def get_reply():
    raise NotImplemented


# Field Size 	Description 	Data type 	Comments
# 8 	        nonce 	        uint64_t 	random nonce
def get_ping():
    nonce = random.getrandbits(64)
    nonce = struct.pack('<Q', nonce)
    return make('ping', nonce)


# Field Size 	Description 	Data type 	Comments
# 8 	        nonce 	        uint64_t 	nonce from ping
def get_pong(nonce):
    nonce = struct.pack('<Q', nonce)
    return make('pong', nonce)


def get_reject():
    raise NotImplemented


# BIP37

# Field Size    Description 	Data type 	Comments
#  ? 	        filter 	        uint8_t[] 	The filter itself is simply a bit field of arbitrary byte-aligned size.
#                                           The maximum size is 36,000 bytes.
# 4 	        nHashFuncs 	    uint32_t 	The number of hash functions to use in this filter. The maximum value
#                                           allowed in this field is 50.
# 4 	        nTweak 	        uint32_t 	A random value to add to the seed value in the hash function used by
#                                           the bloom filter.
# 1 	        nFlags 	        uint8_t 	A set of flags that control how matched items are added to the filter.
def get_filterload(items, fp_rate, tweak, flags, max_items=None):
    if type(items) is not list:
        items = [items]
    if max_items is None:
        n_elements = len(items)
    else:
        n_elements = max_items

    bloom_filter = BloomFilter(n_elements, fp_rate, tweak)
    for item in items:
        bloom_filter.insert(item)

    filter_bytes, num_hash_funcs, tweak = bloom_filter.get_filter_params()
    payload = filter_bytes + struct.pack('<I', num_hash_funcs) + struct.pack('<I', tweak) + struct.pack('B', flags)

    return make('filterload', payload)


# Field Size 	Description 	Data type 	Comments
#  ? 	        data 	        uint8_t[] 	The data element to add to the current filter.
def get_filteradd(data):
    data = binascii.unhexlify(data)[::-1]
    length = len(data)
    payload = get_var_int(length) + data
    return make('filteradd', payload)


def get_filterclear():
    return make('filterclear', b'')


def merkleblock():
    raise NotImplemented


# Note: Support for alert messages has been removed from bitcoin core in March 2016
def get_alert():
    raise NotImplemented


# BIP130

def get_sendheaders():
    return make('sendheaders', b'')


# Added in protocol version 209.
# First 4 bytes of SHA256(SHA256(payload)) in internal byte order.
# If payload is empty, as in verack and getaddr messages, the checksum is always 0x5df6e0e2
# (SHA256(SHA256(<empty string>))).
def get_checksum(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]


# Value 	        Storage length 	Format
# < 0xFD 	        1 	            uint8_t
# <= 0xFFFF 	    3 	            0xFD followed by the length as uint16_t
# <= 0xFFFF FFFF 	5 	            0xFE followed by the length as uint32_t
# - 	            9 	            0xFF followed by the length as uint64_t
def get_var_int(ln):
    if ln < 0xfd:
        return struct.pack('B', ln)
    if ln < 0xffff:
        return b'\xfd' + struct.pack('H', ln)
    if ln < 0xffffffff:
        return b'\xfe' + struct.pack('L', ln)
    return b'\xff' + struct.pack('Q', ln)


# Field Size 	Description 	Data type 	Comments
# 4 	        time 	        uint32 	    the Time (version >= 31402). Not present in version message.
# 8 	        services 	    uint64_t 	same service(s) listed in version
# 16 	        IPv6/4 	        char[16] 	IPv6 address. Network byte order. The original client only supported
#                                           IPv4 and only read the last 4 bytes to get the IPv4 address. However,
#                                           the IPv4 address is written into the message as a 16 byte IPv4-mapped
#                                           IPv6 address
#
# (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
# 2 	        port 	        uint16_t 	port number, network byte order
def net_address(service, ip, port):
    res = (struct.pack('<Q12s', service,
                       b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff') + struct.pack('>4sH', socket.inet_aton(ip),
                                                                                          port))
    return res


# Field Size 	Description 	Data type 	Comments
#  ? 	        length 	        var_int 	Length of the string
#  ? 	        string 	        char[] 	    The string itself (can be empty)
def get_var_str(text):
    return get_var_int(len(text)) + text.encode()
