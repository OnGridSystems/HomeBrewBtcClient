import binascii
import collections
import hashlib
import ipaddress
import struct

import node.message as message
import node.script as script
import node.settings as settings


def get_message(data):
    try:
        index = data.index(settings.MAGIC)
    except ValueError:
        return False
    msg = data[index:]
    length = struct.unpack('<L', msg[16:20])[0]
    checksum = msg[20:24]
    payload = msg[24:24 + length]
    test_checksum = message.get_checksum(payload)
    if test_checksum != checksum:
        raise ValueError('Checksum mismatch')
    return data[:24 + length]


def get_command_name(command):
    name = command[4:16]
    return str(name, 'utf-8').strip('\x00')


# Payload
# Field Size 	Description 	Data type 	Comments
# 4 	        version 	    int32_t 	Identifies protocol version being used by the node
# 8 	        services 	    uint64_t 	bitfield of features to be enabled for this connection
# 8 	        timestamp 	    int64_t 	standard UNIX timestamp in seconds
# 26 	        addr_recv 	    net_addr 	The network address of the node receiving this message
# Fields below require version ≥ 106
# 26 	        addr_from 	    net_addr 	The network address of the node emitting this message
# 8 	        nonce 	        uint64_t 	Node random nonce, randomly generated every time a version packet is sent.
#                               This nonce is used to detect connections to self.
# ? 	        user_agent 	    var_str 	User Agent (0x00 if string is 0 bytes long)
# 4 	        start_height 	int32_t     The last block received by the emitting node
# Fields below require version ≥ 70001
# 1 	        relay 	        bool 	    Whether the remote peer should announce relayed transactions or not,
#                                           see BIP 0037
def get_version(data):
    res_ver = {}
    payload = get_payload(data)
    version = struct.unpack('<L', payload[:4])[0]
    res_ver['version'] = version
    services = struct.unpack('<Q', payload[4:12])[0]
    res_ver['services'] = services
    timestamp = struct.unpack('<Q', payload[12:20])[0]
    res_ver['timestamp'] = timestamp
    addr_recv = get_address(payload[20:46])
    res_ver['addr_recv'] = addr_recv
    addr_from = get_address(payload[46:72])
    res_ver['addr_from'] = addr_from
    nonce = struct.unpack('<Q', payload[72:80])[0]
    res_ver['nonce'] = nonce
    user_agent, offset = parse_var_str(payload[80:])
    user_agent = user_agent.decode()
    res_ver['user_agent'] = user_agent
    start_height = payload[80 + offset:84 + offset]
    start_height = struct.unpack('<L', start_height)[0]
    res_ver['start_height'] = start_height
    # TODO Check for relay
    # return [version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height]
    return res_ver


# Field Size 	Description 	Data type 	Comments
# 4 	        time 	        uint32 	    the Time (version >= 31402). Not present in version message.
# 8 	        services 	    uint64_t 	same service(s) listed in version
# 16 	        IPv6/4 	        char[16] 	IPv6 address. Network byte order. The original client
#                                           only supported IPv4 and only read the last 4 bytes
#                                           to get the IPv4 address. However, the IPv4 address
#                                           is written into the message as a 16 byte
#                                           IPv4-mapped IPv6 address
#
# (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
# 2 	        port 	        uint16_t 	port number, network byte order
def get_addr(addr):
    res = {}
    payload = get_payload(addr)
    res['time'] = struct.unpack('I', payload[:4])[0]
    res['services'] = struct.unpack('<Q', payload[:8])[0]
    ip = payload[8:24]
    port = struct.unpack('>H', payload[24:26])[0]

    r_ip = binascii.hexlify(struct.unpack('<16s', ip)[0]).decode()
    r_ip = ipaddress.IPv6Address(int(r_ip, 16))
    if r_ip.ipv4_mapped:
        r_ip = r_ip.ipv4_mapped.compressed
    else:
        r_ip = r_ip.compressed
    res['ip'] = r_ip
    res['port'] = port
    return res


# Payload:
# Field Size 	Description 	Data type 	    Comments
#  ? 	        count 	        var_int 	    Number of block headers
# 81x? 	        headers 	    block_header[] 	Block headers
def get_headers(data):
    payload = get_payload(data)
    count, offset = parse_var_int(payload)
    headers_arr = []
    headers = payload[offset:]
    while count:
        h = get_header(headers[:81])
        headers = headers[81:]
        headers_arr.append(h)
        count -= 1
    return headers_arr


# Field Size 	Description 	Data type 	Comments
# 4 	        version 	    int32_t 	Block version information (note, this is signed)
# 32 	        prev_block 	    char[32] 	The hash value of the previous block this particular block references
# 32 	        merkle_root 	char[32] 	The reference to a Merkle tree collection which is a hash of all
#                                           transactions related to this block
# 4 	        timestamp 	    uint32_t 	A timestamp recording when this block was created (Will overflow in 2106[2])
# 4 	        bits 	        uint32_t 	The calculated difficulty target being used for this block
# 4 	        nonce 	        uint32_t 	The nonce used to generate this block… to allow variations of the header
#                                           and compute different hashes
# 1 	        txn_count 	    var_int 	Number of transaction entries, this value is always 0
def get_header(header):
    res_hdr = {}
    block_id = get_block_id(header)
    res_hdr['id'] = block_id
    version = struct.unpack('<L', header[:4])[0]
    res_hdr['version'] = version
    prev_block = binascii.hexlify(header[4:36][::-1]).decode()
    res_hdr['prev_block'] = prev_block
    merkle_root = binascii.hexlify(header[36:68][::-1]).decode()
    res_hdr['merkle_root'] = merkle_root
    timestamp = struct.unpack('<I', header[68:72])[0]
    res_hdr['timestamp'] = timestamp
    bits = struct.unpack('<I', header[72:76])[0]
    res_hdr['bits'] = bits
    nonce = struct.unpack('<I', header[76:80])[0]
    res_hdr['nonce'] = nonce
    tx_count = struct.unpack('B', header[80:81])[0]
    res_hdr['tx_count'] = tx_count
    return res_hdr


# Allows a node to advertise its knowledge of one or more objects. It can be received unsolicited,
# or in reply to getblocks.
#
# Payload (maximum 50,000 entries, which is just over 1.8 megabytes):
# Field Size 	Description 	Data type 	Comments
#  ? 	        count 	        var_int 	Number of inventory entries
# 36x? 	        inventory 	    inv_vect[] 	Inventory vectors
def get_inv(data):
    payload = get_payload(data)
    count, offset = parse_var_int(payload)
    vectors = payload[offset:]
    result = [count]
    while count:
        inv_type = struct.unpack("<L", vectors[:4])[0]
        inv_hash = vectors[4:36]
        inv_hash = binascii.hexlify(inv_hash[::-1]).decode()
        result.append([inv_type, inv_hash])
        vectors = vectors[36:]
        count -= 1
    return result


# Field Size 	Description 	Data type 	Comments
# 4 	        time 	        uint32 	    the Time (version >= 31402). Not present in version message.
# 8 	        services 	    uint64_t 	same service(s) listed in version
# 16 	        IPv6/4 	        char[16] 	IPv6 address. Network byte order. The original client
#                                           only supported IPv4 and only read the last 4 bytes
#                                           to get the IPv4 address. However, the IPv4 address
#                                           is written into the message as a 16 byte
#                                           IPv4-mapped IPv6 address
#
# (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
# 2 	        port 	        uint16_t 	port number, network byte order
# Example
# 01 00 00 00 00 00 00 00                         - 1 (NODE_NETWORK: see services listed under version command)
# 00 00 00 00 00 00 00 00 00 00 FF FF 0A 00 00 01 - IPv6: ::ffff:a00:1 or IPv4: 10.0.0.1
# 20 8D                                           - Port 8333
def get_address(address, version=None):
    result = []
    if version:  # or version < 31402:  # and struct.unpack('<L', version)[0] >= 31402:
        time = address[:4]
        address = address[4:]
        result.append(time)
    service = struct.unpack('<Q', address[:8])[0]
    ip = address[8:24]
    port = struct.unpack('>H', address[24:26])[0]

    r_ip = binascii.hexlify(struct.unpack('<16s', ip)[0]).decode()
    r_ip = ipaddress.IPv6Address(int(r_ip, 16))
    if r_ip.ipv4_mapped:
        r_ip = r_ip.ipv4_mapped.compressed
    else:
        r_ip = r_ip.compressed

    result.append(service)
    result.append(r_ip)
    result.append(port)
    return result


# tx describes a bitcoin transaction
# Field Size 	Description 	Data type 	        Comments
# 4 	        version 	    int32_t 	        Transaction data format version (note, this is signed)
# 0 or 2 	    flag 	        optional uint8_t[2] If present, always 0001, and indicates the presence of witness data
# 1+ 	        tx_in count 	var_int 	        Number of Transaction inputs (never zero)
# 41+ 	        tx_in 	        tx_in[] 	        A list of 1 or more transaction inputs or sources for coins
# 1+ 	        tx_out count 	var_int 	        Number of Transaction outputs
# 9+ 	        tx_out 	        tx_out[] 	        A list of 1 or more transaction outputs or destinations for coins
# 0+ 	        tx_witnesses 	tx_witness[] 	    A list of witnesses, one for each input; omitted if flag is omitted
#                                                   above
# 4 	        lock_time 	    uint32_t 	        The block number or timestamp at which this transaction is unlocked:
#                                                   Value 	        Description
#                                                   0 	            Not locked
#                                                   < 500000000 	Block number at which this transaction is unlocked
#                                                   >= 500000000 	UNIX timestamp at which this transaction is unlocked
#
#                                                   If all TxIn inputs have final (0xffffffff) sequence numbers then
#                                                   lock_time is irrelevant. Otherwise, the transaction may not be
#                                                   added to a block until after lock_time (see NLockTime).
def get_tx(tx):
    res_tx = collections.OrderedDict()
    # tx can be standalone message, or came from block
    # settings.MAGIC
    # if tx.startswith(b'\x0b\x11\t\x07'):
    if tx.startswith(settings.MAGIC):
        payload = get_payload(tx)
    else:
        payload = tx

    result_tx = []
    tx_size = 0

    version = struct.unpack('<L', payload[:4])[0]
    tx_size += 4

    result_tx.append(version)
    res_tx['version'] = version

    # detect flag
    flag_offset = 0
    # tx in count cant be zero
    if payload[4:5] == b'\x00':
        flag_offset = 2
        flag = 1
        result_tx.append(flag)
        res_tx['flag'] = flag
        tx_size += 2
    count, offset = parse_var_int(payload[4 + flag_offset:])
    tx_in_count = count
    tx_size += offset

    result_tx.append(tx_in_count)
    res_tx['tx_in_count'] = count

    txins = payload[4 + flag_offset + offset:]
    tx_in = []
    while count:
        t, size = get_txin(txins)
        tx_in.append(t)
        txins = txins[size:]

        tx_size += size
        count -= 1

    result_tx.append(tx_in)
    res_tx['tx_in'] = tx_in
    # tx_out
    count, offset = parse_var_int(txins)
    tx_out_count = count
    tx_size += offset

    result_tx.append(tx_out_count)
    res_tx['tx_out_count'] = count

    tx_outs = txins[offset:]
    tx_out = []
    while count:
        t, size = get_txout(tx_outs)
        tx_out.append(t)
        tx_outs = tx_outs[size:]

        tx_size += size
        count -= 1

    result_tx.append(tx_out)
    res_tx['tx_out'] = tx_out

    # witness
    if flag_offset:
        witnesses = []
        witness = tx_outs
        wtn_count, offset = parse_var_int(witness)
        witness = witness[offset:]
        while wtn_count:
            count, offset = parse_var_int(witness)
            witness = witness[offset:]
            witnesses.append(binascii.hexlify(witness[:count]).decode())
            witness = witness[:count]
            tx_outs = witness
            wtn_count -= 1
        res_tx['tx_witnesses'] = witnesses

    lock_time = tx_outs[:4]
    lock_time = struct.unpack('<I', lock_time)[0]
    # lock_time = binascii.hexlify(lock_time).decode()

    tx_size += 4
    result_tx.append(lock_time)
    res_tx['lock_time'] = lock_time

    res_tx['tx_id'] = get_tx_id(payload[:tx_size])
    res_tx.move_to_end('tx_id', False)
    return res_tx, tx_size


# Field Size 	Description 	    Data type 	Comments
# 36 	        previous_output 	outpoint 	The previous output transaction reference, as an OutPoint structure
# 1+ 	        script length 	    var_int 	The length of the signature script
#  ? 	        signature script 	uchar[] 	Computational Script for confirming transaction authorization
# 4 	        sequence 	        uint32_t 	Transaction version as defined by the sender. Intended for "replacement"
#                                               of transactions when information is updated before inclusion into
#                                               a block.
def get_txin(tx_in):
    res_tx_in = collections.OrderedDict()
    previous_output = get_outpoint(tx_in[:36])
    res_tx_in['previous_output'] = previous_output
    count, offset = parse_var_int(tx_in[36:])
    script_length = count
    res_tx_in['script_length'] = script_length
    total_offset = offset + script_length
    signature_script = tx_in[36 + offset:36 + total_offset]
    signature_script = binascii.hexlify(signature_script).decode()
    res_tx_in['signature_script'] = signature_script
    sequence = tx_in[36 + total_offset:40 + total_offset]
    sequence = struct.unpack('<I', sequence)[0]
    res_tx_in['sequence'] = sequence
    try:
        res_tx_in['address'] = script.scriptsig2adddr(signature_script)
    except:
        res_tx_in['address'] = 'unk'
    return res_tx_in, total_offset + 40


# Field Size 	Description 	Data type 	Comments
# 32 	        hash 	        char[32] 	The hash of the referenced transaction.
# 4 	        index 	        uint32_t 	The index of the specific output in the transaction.
#                               The first output is 0, etc.
def get_outpoint(data):
    outpoint = {}
    hsh = data[:32]
    hsh = binascii.hexlify(hsh[::-1]).decode()
    outpoint['hash'] = hsh
    index = struct.unpack('<I', data[32:36])[0]
    outpoint['index'] = index
    return outpoint


# The TxOut structure consists of the following fields:
# Field Size 	Description 	    Data type 	Comments
# 8 	        value 	            int64_t 	Transaction Value
# 1+ 	        pk_script length 	var_int 	Length of the pk_script
#  ? 	        pk_script 	        uchar[] 	Usually contains the public key as a Bitcoin script setting up
#                                               conditions to claim this output.
def get_txout(tx_out):
    res_tx_out = collections.OrderedDict()
    value = tx_out[:8]
    value = struct.unpack('Q', value)[0]
    res_tx_out['value'] = value
    pk_script_length, offset = parse_var_int(tx_out[8:])
    res_tx_out['pk_script_length'] = pk_script_length
    pk_script = tx_out[8 + offset:8 + offset + pk_script_length]
    pk_script = binascii.hexlify(pk_script).decode()
    res_tx_out['pk_script'] = pk_script
    res_tx_out['address'] = script.pkscript2addr(pk_script)
    return res_tx_out, 8 + offset + pk_script_length


# Field Size 	Description 	Data type 	Comments
# 4 	        version 	    int32_t 	Block version information (note, this is signed)
# 32 	        prev_block 	    char[32] 	The hash value of the previous block this particular block references
# 32 	        merkle_root 	char[32] 	The reference to a Merkle tree collection which is a hash of all
#                                           transactions related to this block
# 4 	        timestamp 	    uint32_t 	A Unix timestamp recording when this block was created (Currently limited
#                                           to dates before the year 2106!)
# 4 	        bits 	        uint32_t 	The calculated difficulty target being used for this block
# 4 	        nonce 	        uint32_t 	The nonce used to generate this block… to allow variations of the header
#                                           and compute different hashes
#  ? 	        txn_count 	    var_int 	Number of transaction entries
#  ? 	        txns 	        tx[] 	    Block transactions, in format of "tx" command
def get_block(block):
    res_block = collections.OrderedDict()
    payload = get_payload(block)
    res_block['block_id'] = get_block_id(payload)
    version = struct.unpack('<L', payload[:4])[0]
    res_block['version'] = version
    prev_block = payload[4:36]
    prev_block = binascii.hexlify(prev_block[::-1]).decode()
    res_block['prev_block'] = prev_block
    merkle_root = payload[36:68]
    merkle_root = binascii.hexlify(merkle_root[::-1]).decode()
    res_block['merkle_root'] = merkle_root
    timestamp = struct.unpack('<I ', payload[68:72])[0]
    res_block['timestamp'] = timestamp
    bits = struct.unpack('<I', payload[72:76])[0]
    res_block['bits'] = bits
    nonce = struct.unpack('<I', payload[76:80])[0]
    res_block['nonce'] = nonce
    count, offset = parse_var_int(payload[80:])
    txn_count = count
    res_block['txn_count'] = txn_count
    txs = payload[80 + offset:]
    transactions = []
    while count:
        tx, size = get_tx(txs)
        transactions.append(tx)
        txs = txs[size:]
        count -= 1

    res_block['txns'] = transactions
    return res_block


def get_tx_from_block(block):
    return get_block(block)['txns']


# Note: Support for alert messages has been removed from bitcoin core in March 2016
def get_alert(alert):
    payload = get_payload(alert)
    return payload


# Field Size 	Description 	Data type 	Comments
# 8 	        nonce 	        uint64_t 	random nonce
def get_ping(data):
    payload = get_payload(data)
    return struct.unpack('<Q', payload[:8])[0]


# Extract payload from message
def get_payload(data):
    if len(data) < 24:
        raise ValueError('Data too short')
    length = data[16:20]
    checksum = data[20:24]
    length = struct.unpack('<L', length)[0]
    payload = data[24:]
    if len(payload) < length:
        raise ValueError('Data too short')
    if message.get_checksum(payload) != checksum:
        print(data)
        raise ValueError('Checksum mismatch')
    return payload


# Value 	        Storage length 	Format
# < 0xFD 	        1 	            uint8_t
# <= 0xFFFF 	    3 	            0xFD followed by the length as uint16_t
# <= 0xFFFF FFFF 	5 	            0xFE followed by the length as uint32_t
# - 	            9 	            0xFF followed by the length as uint64_t
def parse_var_int(data):
    """
    Parse integer packed in variable integer format
    :param data: bytes leaded by var_int
    :return: Tuple of integer value and total length of var_int bytes
    """
    ln = int.from_bytes(data[:1], byteorder='little')
    if ln < 0xfd:
        return ln, 1
    if ln == 0xfd:
        return int.from_bytes(data[1:3], byteorder='little'), 3
    if ln == 0xfe:
        return int.from_bytes(data[1:5], byteorder='little'), 5
    if ln < 0xff:
        return int.from_bytes(data[1:9], byteorder='little'), 9


def parse_var_str(data):
    """
    Parse var_string
    :param data: Var_string leading by string length packed in var_int
    :return: Tuple of string value and total length of string itself and leading var_int
    """
    length, offset = parse_var_int(data)
    total_length = offset + length
    string = data[offset: total_length]
    return string, total_length


# TODO check for malleability BIP62, BIP66
def get_tx_id(raw_tx):
    return binascii.hexlify(hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()[::-1]).decode()


def get_block_id(raw_block):
    return binascii.hexlify(hashlib.sha256(hashlib.sha256(raw_block[:80]).digest()).digest()[::-1]).decode()
