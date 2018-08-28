# 01000000 ........................... Block version: 1
# 82bb869cf3a793432a66e826e05a6fc3
# 7469f8efb7421dc88067010000000000 ... Hash of previous block's header
# 7f16c5962e8bd963659c793ce370d95f
# 093bc7e367117b3c30c1f8fdd0d97287 ... Merkle root
# 76381b4d ........................... Time: 1293629558
# 4c86041b ........................... nBits: 0x04864c * 256**(0x1b-3)
# 554b8529 ........................... Nonce
#
# 07000000 ........................... Transaction count: 7
# 04 ................................. Hash count: 4
#
# 3612262624047ee87660be1a707519a4
# 43b1c1ce3d248cbfc6c15870f6c5daa2 ... Hash #1
# 019f5b01d4195ecbc9398fbf3c3b1fa9
# bb3183301d7a1fb3bd174fcfa40a2b65 ... Hash #2
# 41ed70551dd7e841883ab8f0b16bf041
# 76b7d1480e4f0af9f3d4c3595768d068 ... Hash #3
# 20d2a7bc994987302e5b1ac80fc425fe
# 25f8b63169ea78e68fbaaefa59379bbf ... Hash #4
#
# 01 ................................. Flag bytes: 1
# 1d ................................. Flags: 1 0 1 1 1 0 0 0

import binascii
import struct
from ..node.msg_parser import parse_var_int, get_payload

merkle = b'0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b852907000000043612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b6541ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d06820d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf011d'

# 000000000000004f38d386efff6e86901b9d268ecc040216ea7cddd765090607
# Merkle Root 	9615ae40a2833f5ba1d44c03ffd8c5ba41bd209a80b2e293436b732c56d5180e
block = b'\x0b\x11\t\x07merkleblock\x00\xb9\x01\x00\x00\xe3 \xf5\x98\x00\x00\x00 \x8b\x1e\x86\xe6+\x99|\x91\x80\xa3W\xc7\x85%@\x06}\x13\xb8\xafc,H;\xad\x00\x00\x00\x00\x00\x00\x00\x0e\x18\xd5V,skC\x93\xe2\xb2\x80\x9a \xbdA\xba\xc5\xd8\xff\x03L\xd4\xa1[?\x83\xa2@\xae\x15\x96\xdd*h[\x8e\xf7\x00\x1a\r \xc8#\xa5\x0c\x00\x00\x0b\xdc\xe3v-\x89Bip\x18\xdeH)\x1eG\x9d\xf4\x0eO\xf2q\x9b\xd3\xcb\xfe\xde\xe2\x94l\xfa\xeb\xec\xb1=(B\x96\x1b\xfcI8Fn\xa7\x94\xb3\xd1\xbd\t\xb4\\\x05\xa6\x91jG|$\x7fD\xc5\xec!\xee\x03Q\xf0UL\x99\x08\xa4\xe2\xd2*\x0c\xfa\x06=\xd5\x936\x9a"\xc7\x9d"{b\x8e\xceX\xd6+\xc3f\x1b`\x0bM$\xf9\xb2\x98c\x9a\xb9\xfdN\xf7\xc8\x0c\xabA%\xb1\xf3\x06\xa2\xdb\x83F`lE\x96x~\xed\n-t\xf4\x8e\xaf~\xa7\xb5\xc0\xbb\xe6\x07\xaf\xefD\xb1\xdb\x89\x16G\xb7\x05z\xa8\xb5\x9e\xa2\x89\xf4\xd6\xe6\x1c\xec\xac\x02w\xb1\xcc`\xa6\xcc\x90\xbb\xc2\xf9\x19\xe9\xdc\x13w\xab\xf2~\x92t\x0f%\xd5\x03&4\xc2\xd3\xf2 \x01O} \x86\x97\xf6\x01H!\xde\x17n\xd7\x8em\xfc\xf8V\xf4\xf8\x05\xf9\xf1l\xbe\xdbei\xadd/|e\x91P\x80\xc4\x1a\xb9\n\xb61,\x87`L1u Tm\xc4\xe5NDP3\x91\xe4V\x1c\xb9\xe4p\xf5v\xdbO\xc6z\xd3\xe2\xfcD\xea\xaf\x1f\xbe\x92.\xa1P\x9a\x1f\x17\xde\x1f\xb04\xde\xb8\x13\x81\x182N\xbc\xc6\x8a;\x9bz\xfb\xb5\xbc\xf2\x10\xa4,\xba\xaa\x92\x94\x91_\x96\xe4\xdb(\xe6\xf5\x01\xff\x84[\x1d\xdb\xca\x90_OzM/\x0ew^X\xc7\xb6L\xdf\xa5\xaa]\xecPi\xe2\xe3\x86\xa5^\xf5\x13\x91\xfe\x03\xf5\xdd\x01'
nomatches = b'\x0b\x11\t\x07merkleblock\x00w\x00\x00\x00\x8f\xd8\xcc,\x00\x00\x00 \x0c\xf0\xb5p0f\xe7\xe7dD\x8d\xe7]\xaf+\xb7w\xa2\xec\x83\x1e\xd1\xf4\xbb\xa7\x00\x00\x00\x00\x00\x00\x00\xdb\x0el%S\xac\xb7\xf6\x90\x94\xb9.\xb6\x8b"&\xef+:J\x15\xb0a\xe2 ;L\x16\xc7P\x01\xd6\x8a\x9f\x86[g\xd8\x00\x1a\t\xc8\xccU\xa6\x00\x00\x00\x01\xdb\x0el%S\xac\xb7\xf6\x90\x94\xb9.\xb6\x8b"&\xef+:J\x15\xb0a\xe2 ;L\x16\xc7P\x01\xd6\x01\x00'


# Field Size 	Description 	    Data type 	Comments
# 4 	        version 	        int32_t 	Block version information, based upon the software version creating this
#                                               block (note, this is signed)
# 32 	        prev_block 	        char[32] 	The hash value of the previous block this particular block references
# 32 	        merkle_root 	    char[32] 	The reference to a Merkle tree collection which is a hash of all
#                                               transactions related to this block
# 4 	        timestamp 	        uint32_t 	A timestamp recording when this block was created (Limited to 2106!)
# 4 	        bits 	            uint32_t 	The calculated difficulty target being used for this block
# 4 	        nonce 	            uint32_t 	The nonce used to generate this block… to allow variations of the header
#                                               and compute different hashes
# 4 	        total_transactions 	uint32_t 	Number of transactions in the block (including unmatched ones)
#  ? 	        hashes 	            uint256[] 	hashes in depth-first order (including standard varint size prefix)
#  ? 	        flags 	            byte[] 	    flag bits, packed per 8 in a byte, least significant bit first
#                                               (including standard varint size prefix)


def parse_merkleblock(data):
    result = {}
    version = struct.unpack('<L', data[:4])[0]
    result['version'] = version
    prev_block = data[4:36]
    prev_block = binascii.hexlify(prev_block[::-1]).decode()
    result['prev_block'] = prev_block
    merkle_root = data[36:68]
    merkle_root = binascii.hexlify(merkle_root[::-1]).decode()
    result['merkle_root'] = merkle_root
    timestamp = struct.unpack('<I ', data[68:72])[0]
    result['timestamp'] = timestamp
    bits = struct.unpack('<I', data[72:76])[0]
    result['bits'] = bits
    nonce = struct.unpack('<I', data[76:80])[0]
    result['nonce'] = nonce
    total_transactions = int.from_bytes(data[80:84], byteorder='little')
    result['total_transactions'] = total_transactions
    # hashes
    count, offset = parse_var_int(data[84:])
    hashes = data[84 + offset:]
    hash_arr = []
    while count:
        hash = hashes[:32]
        hash = binascii.hexlify(hash[::-1])
        hash_arr.append(hash)
        hashes = hashes[32:]
        count -= 1
    result['hashes'] = hash_arr
    count, offset = parse_var_int(hashes)
    flags = hashes[offset:offset + count]
    result['flags'] = flags
    result['flags2'] = get_bits(flags)
    return result


def get_bits(data):
    count = len(data) * 8
    data = int.from_bytes(data, byteorder='big')
    s = ''
    while count:
        x = data & 1
        s += str(x)
        print(x, end='')
        data = data >> 1
        count -= 1
    return s


if __name__ == '__main__':
    payload = get_payload(block)
    parse_merkleblock(payload)

    payload = get_payload(nomatches)
    parse_merkleblock(payload)

    payload = get_payload(merkle)
    r = parse_merkleblock(payload)
    print(r)

    parse_merkleblock(binascii.unhexlify(merkle))
    get_bits(b'\x1d')
    print()

    s = '10111000'
    for t in s:
        print(t)
