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
import hashlib
import struct
from node.msg_parser import parse_var_int, get_payload

# 000000000000004f38d386efff6e86901b9d268ecc040216ea7cddd765090607
# Merkle Root 	9615ae40a2833f5ba1d44c03ffd8c5ba41bd209a80b2e293436b732c56d5180e
match_block = b'\x0b\x11\t\x07merkleblock\x00\xb9\x01\x00\x00\xe3 \xf5\x98\x00\x00\x00 \x8b\x1e\x86\xe6+\x99|\x91\x80\xa3W\xc7\x85%@\x06}\x13\xb8\xafc,H;\xad\x00\x00\x00\x00\x00\x00\x00\x0e\x18\xd5V,skC\x93\xe2\xb2\x80\x9a \xbdA\xba\xc5\xd8\xff\x03L\xd4\xa1[?\x83\xa2@\xae\x15\x96\xdd*h[\x8e\xf7\x00\x1a\r \xc8#\xa5\x0c\x00\x00\x0b\xdc\xe3v-\x89Bip\x18\xdeH)\x1eG\x9d\xf4\x0eO\xf2q\x9b\xd3\xcb\xfe\xde\xe2\x94l\xfa\xeb\xec\xb1=(B\x96\x1b\xfcI8Fn\xa7\x94\xb3\xd1\xbd\t\xb4\\\x05\xa6\x91jG|$\x7fD\xc5\xec!\xee\x03Q\xf0UL\x99\x08\xa4\xe2\xd2*\x0c\xfa\x06=\xd5\x936\x9a"\xc7\x9d"{b\x8e\xceX\xd6+\xc3f\x1b`\x0bM$\xf9\xb2\x98c\x9a\xb9\xfdN\xf7\xc8\x0c\xabA%\xb1\xf3\x06\xa2\xdb\x83F`lE\x96x~\xed\n-t\xf4\x8e\xaf~\xa7\xb5\xc0\xbb\xe6\x07\xaf\xefD\xb1\xdb\x89\x16G\xb7\x05z\xa8\xb5\x9e\xa2\x89\xf4\xd6\xe6\x1c\xec\xac\x02w\xb1\xcc`\xa6\xcc\x90\xbb\xc2\xf9\x19\xe9\xdc\x13w\xab\xf2~\x92t\x0f%\xd5\x03&4\xc2\xd3\xf2 \x01O} \x86\x97\xf6\x01H!\xde\x17n\xd7\x8em\xfc\xf8V\xf4\xf8\x05\xf9\xf1l\xbe\xdbei\xadd/|e\x91P\x80\xc4\x1a\xb9\n\xb61,\x87`L1u Tm\xc4\xe5NDP3\x91\xe4V\x1c\xb9\xe4p\xf5v\xdbO\xc6z\xd3\xe2\xfcD\xea\xaf\x1f\xbe\x92.\xa1P\x9a\x1f\x17\xde\x1f\xb04\xde\xb8\x13\x81\x182N\xbc\xc6\x8a;\x9bz\xfb\xb5\xbc\xf2\x10\xa4,\xba\xaa\x92\x94\x91_\x96\xe4\xdb(\xe6\xf5\x01\xff\x84[\x1d\xdb\xca\x90_OzM/\x0ew^X\xc7\xb6L\xdf\xa5\xaa]\xecPi\xe2\xe3\x86\xa5^\xf5\x13\x91\xfe\x03\xf5\xdd\x01'
nomatch_block = b'\x0b\x11\t\x07merkleblock\x00w\x00\x00\x00\x8f\xd8\xcc,\x00\x00\x00 \x0c\xf0\xb5p0f\xe7\xe7dD\x8d\xe7]\xaf+\xb7w\xa2\xec\x83\x1e\xd1\xf4\xbb\xa7\x00\x00\x00\x00\x00\x00\x00\xdb\x0el%S\xac\xb7\xf6\x90\x94\xb9.\xb6\x8b"&\xef+:J\x15\xb0a\xe2 ;L\x16\xc7P\x01\xd6\x8a\x9f\x86[g\xd8\x00\x1a\t\xc8\xccU\xa6\x00\x00\x00\x01\xdb\x0el%S\xac\xb7\xf6\x90\x94\xb9.\xb6\x8b"&\xef+:J\x15\xb0a\xe2 ;L\x16\xc7P\x01\xd6\x01\x00'


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
        hash = binascii.hexlify(hash[::-1]).decode()
        hash_arr.append(hash)
        hashes = hashes[32:]
        count -= 1
    result['hashes'] = hash_arr
    count, offset = parse_var_int(hashes)
    flags = hashes[offset:offset + count]
    result['flags'] = flags
    return result


class PartialMerkleTree:
    def __init__(self, tx_count, flags, hashes):
        self.tx_count = tx_count
        self.flags = self.__parse_bits(flags)
        self.hashes = self.__parse_hashes(hashes)
        self.top = 0
        self.widths = {}
        while self.__tree_width(self.top) > 1:
            self.widths[self.top] = self.__tree_width(self.top)
            self.top += 1
        self.height = 0
        self.hash_length = len(self.hashes)
        self.matches = []
        self.nodes = {self.top: {0: None}}
        self.merkle_root = b'' if self.hash_length > 1 else self.hashes[0]
        self.build_partial_tree()

    def __parse_bits(self, data):
        result = []
        for b in data:
            bits = 8
            while bits:
                bit = b & 1
                result.append(bit)
                b = b >> 1
                bits -= 1
        return result

    def __parse_hashes(self, hashes):
        return [binascii.unhexlify(h)[::-1] for h in hashes]

    def __tree_width(self, height):
        return (self.tx_count + (1 << height) - 1) >> height

    def __add_node(self, height, hash_index=None):
        # skip top
        if height == self.top:
            return
        # calc index and add
        index = max(self.nodes[height + 1].keys()) * 2
        # print(index)
        # calc value
        value = None
        if hash_index is not None:
            value = self.hashes[hash_index]

        if height not in self.nodes.keys():
            self.nodes[height] = {index: value}
            return
        # adjust index
        if index in self.nodes[height].keys():
            index += 1
        if index in self.nodes[height].keys():
            raise ValueError('double index')
        self.nodes[height][index] = value

    def __build_up(self, height):
        # check for root
        if height == self.top:
            return height
        x = max(self.nodes[height].keys())
        # left or right
        # left element always got offset 0 or even (offset not serial number)
        if x == 0 or x % 2 == 0:
            # got left
            # no value?
            if self.nodes[height][x] is None:
                return height

            # no right?
            if x + 1 == self.widths[height]:
                h = self.nodes[height][x]
                result = self.__get_hash(h + h)
                # return value
                if self.widths[height + 1] - 1 not in self.nodes[height + 1].keys():
                    raise ValueError('no parent node')
                if self.nodes[height + 1][self.widths[height + 1] - 1] is not None:
                    raise ValueError('already has value')
                self.nodes[height + 1][self.widths[height + 1] - 1] = result
                height = self.__build_up(height + 1)
            return height
        # got right
        else:
            # no value?
            if self.nodes[height][x] is None:
                return height
            # got left pair
            if x - 1 in self.nodes[height].keys() and self.nodes[height][x - 1] is not None:
                h1 = self.nodes[height][x - 1]
                h2 = self.nodes[height][x]
                result = self.__get_hash(h1 + h2)
                parent = int((x - 1) / 2)
                if parent in self.nodes[height + 1].keys() and self.nodes[height + 1][parent] is None:
                    self.nodes[height + 1][parent] = result
                    height = self.__build_up(height + 1)
                    return height

    def __get_hash(self, data):
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def build_partial_tree(self):
        # if single hash and no flags
        if self.hash_length == 1 and self.flags[0] == 0:
            self.merkle_root = self.hashes[0]
            return

        flag_index = 0
        hash_index = 0
        height = self.top

        while hash_index < self.hash_length:
            # if non TXID
            if height != 0:
                if self.flags[flag_index]:
                    # The hash needs to be computed. Process the left child node to get its hash; process the right
                    # child node to get its hash; then concatenate the two hashes as 64 raw bytes and hash them
                    # to get this node’s hash.
                    self.__add_node(height)
                    height -= 1
                    flag_index += 1
                else:
                    # Use the next hash as this node’s hash. Don’t process any descendant nodes.
                    self.__add_node(height, hash_index=hash_index)
                    hash_index += 1
                    flag_index += 1
                    height = self.__build_up(height)
            # if TXID
            else:
                if self.flags[flag_index]:
                    #  Use the next hash as this node’s TXID, and mark this transaction as matching the filter.
                    self.matches.append(self.hashes[hash_index])
                # Use the next hash as this node’s TXID, but this transaction didn’t match the filter.
                self.__add_node(height, hash_index=hash_index)
                hash_index += 1
                flag_index += 1
                height = self.__build_up(height)
        # post checks
        if hash_index < self.hash_length:
            raise ValueError('got unused hashes')
        if flag_index + 1 <= len(self.flags) - 8 and 1 not in self.flags[flag_index:]:
            raise ValueError('got unused bits')
        self.merkle_root = self.nodes[self.top][0]

    def get_matches(self):
        if not self.matches:
            return None
        return [binascii.hexlify(h[::-1]).decode() for h in self.matches]

    def get_merkle_root(self):
        return binascii.hexlify(self.merkle_root[::-1]).decode()


if __name__ == '__main__':
    payload = get_payload(match_block)
    m = parse_merkleblock(payload)
    p = PartialMerkleTree(m['total_transactions'], m['flags'], m['hashes'])
    assert p.merkle_root() == m['merkle_root'], 'merkle_root mismatch'

    payload = get_payload(nomatch_block)
    m = parse_merkleblock(payload)
    p = PartialMerkleTree(m['total_transactions'], m['flags'], m['hashes'])
    assert p.merkle_root() == m['merkle_root'], 'merkle_root mismatch'
