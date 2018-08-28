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

merkle = b'0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b852907000000043612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b6541ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d06820d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf011d'


def parse_merkleblock(data):
    result = {}
    version = struct.unpack('<L', data[:4])[0]
    prev_block = data[4:36]
    prev_block = binascii.hexlify(prev_block[::-1]).decode()
    merkle_root = data[36:68]
    timestamp = struct.unpack('<I ', data[68:72])[0]
    bits = struct.unpack('<I', data[72:76])[0]
    nonce = struct.unpack('<I', data[76:80])[0]
    total_transactions = data[80:84]
    total_transactions = int.from_bytes(total_transactions, byteorder='little')
    result['version'] = version
    result['prev_block'] = prev_block
    result['merkle_root'] = merkle_root
    result['timestamp'] = timestamp
    result['bits'] = bits
    result['nonce'] = nonce
    result['total_transactions'] = total_transactions
    # hashes
    count, offset = parse_var_int(data[84:])
    hashes = data[84 + offset:]
    h_arr = []
    while count:
        h = hashes[:32]
        h = binascii.hexlify(h)
        h_arr.append(h)
        hashes = hashes[32:]
        count -= 1
    result['hashes'] = h_arr
    count, offset = parse_var_int(hashes)
    flags = hashes[offset:offset + count]
    result['flags'] = flags
    print(flags)
    return result


def get_bits(data):
    count = len(data) * 8
    data = int.from_bytes(data, byteorder='big')
    while count:
        x = data & 1
        print(x, end='')
        data = data >> 1
        count -= 1


def build_tree():
    pass


if __name__ == '__main__':
    payload = get_payload(merkle)
    r = parse_merkleblock(payload)
    print(r)

    parse_merkleblock(binascii.unhexlify(merkle))
    get_bits(b'\x1d')
    print()

    s = '10111000'
    for t in s:
        print(t)
