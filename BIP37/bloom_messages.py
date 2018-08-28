import hashlib
import math
import struct
from math import log
from pycoin.encoding import bitcoin_address_to_hash160_sec

LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
LN2 = 0.6931471805599453094172321214581765680755001343602552

DEFAULT_FALSE_POSITIVE_RATE = 0.0001
DEFAULT_TWEAK = 0

# (36,000: selected as it represents a filter of 20,000 items with false
# positive rate of < 0.1% or 10,000 items and a false positive rate of < 0.0001%).
MAX_BLOOM_FILTER_SIZE = 36000
MAX_HASH_COUNT = 50


# BIP 37


# Number of bytes in payload. The current maximum number of bytes (MAX_SIZE) allowed in the payload by Bitcoin Core
# is 32 MiB—messages with a payload size larger than this will be dropped or rejected.
def make(magic, command, payload):
    checksum = get_checksum(payload)
    return magic + struct.pack('<12sL4s',
                               bytes(command.encode('utf-8')),
                               len(payload),
                               checksum) + payload


# Added in protocol version 209.
# First 4 bytes of SHA256(SHA256(payload)) in internal byte order.
# If payload is empty, as in verack and getaddr messages, the checksum is always 0x5df6e0e2
# (SHA256(SHA256(<empty string>))).
def get_checksum(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]


# Field Size    Description 	Data type 	Comments
#  ? 	        filter 	        uint8_t[] 	The filter itself is simply a bit field of arbitrary byte-aligned size.
#                                           The maximum size is 36,000 bytes.
# 4 	        nHashFuncs 	    uint32_t 	The number of hash functions to use in this filter. The maximum value
#                                           allowed in this field is 50.
# 4 	        nTweak 	        uint32_t 	A random value to add to the seed value in the hash function used by
#                                           the bloom filter.
# 1 	        nFlags 	        uint8_t 	A set of flags that control how matched items are added to the filter.
def filterload(data, nFPRate=DEFAULT_FALSE_POSITIVE_RATE, nTweak=DEFAULT_TWEAK):
    if type(data) is not list:
        data = [data]

    # falsePositiveRate

    # Let nElements be the number of elements you wish to insert into the set and P be the probability
    # of a false positive, where 1.0 is "match everything" and zero is unachievable.
    nElements = len(data)
    P = nFPRate

    nFlags = 0

    # The size S of the filter in bytes is given by (-1 / pow(log(2), 2) * N * log(P)) / 8. Of course you must ensure it
    # does not go over the maximum size (36,000: selected as it represents a filter of 20,000 items with false positive
    # rate of < 0.1% or 10,000 items and a false positive rate of < 0.0001%).
    S = int(min((-1 / pow(log(2), 2) * nElements * log(P)) / 8, MAX_BLOOM_FILTER_SIZE))

    # The number of hash functions required is given by S * 8 / N * log(2).
    nHashNum = int(min(S * 8 / nElements * LN2, MAX_HASH_COUNT))

    # TODO check S and nHashNum results with original client

    bit_count = 8 * nElements
    bit_mask = bytearray(S)

    # addresses to hashes
    v = []
    for h in data:
        if h[0] in ['m', 'n']:
            v.append(bitcoin_address_to_hash160_sec(h, address_prefix=b'\x6F'))
        else:
            v.append(h)

    # use methods from pycoinnet for now
    def set_bit(bm, v):
        byte_index, mask = _index_for_bit(v)
        bm[byte_index] |= mask
        return bm

    def _index_for_bit(v):
        v %= bit_count
        byte_index, mask_index = divmod(v, 8)
        mask = [1, 2, 4, 8, 16, 32, 64, 128][mask_index]
        return byte_index, mask

    for hash in v:
        for hash_index in range(nHashNum):
            seed = hash_index * 0xFBA4C795 + nTweak
            x = murmur3(hash, seed=seed) % bit_count
            bit_mask = set_bit(bit_mask, x)

    return bit_mask


# /*
#  * The ideal size for a bloom filter with a given number of elements and false positive rate is:
#  * - nElements * log(fp rate) / ln(2)^2
#  * We ignore filter parameters which will create a bloom filter larger than the protocol limits
#  */
def calc_size(element_count, false_positive_probability):
    # The size S of the filter in bytes is given by
    # (-1 / pow(log(2), 2) * N * log(P)) / 8
    # Of course you must ensure it does not go over the maximum size

    lfpp = math.log(false_positive_probability)
    return min(MAX_BLOOM_FILTER_SIZE, int(((-1 / pow(LN2, 2) * element_count * lfpp) + 7) // 8))


def get_filterload():
    # payload = b'\x02\xb0Z\x0b\x00\x00\x00\x00\x00\x00\x00\x00'
    payload = b'\x02B\x9d\x0b\x00\x00\x00\x00\x00\x00\x00\x00'
    return make(b'\x0B\x11\x09\x07', 'filterload', payload)


def get_filterclear():
    return make(b'\x0B\x11\x09\x07', 'filterclear', b'')


# http://stackoverflow.com/questions/13305290/is-there-a-pure-python-implementation-of-murmurhash

def murmur3(data, seed=0):
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    length = len(data)
    h1 = seed
    roundedEnd = (length & 0xfffffffc)  # round down to 4 byte block
    for i in range(0, roundedEnd, 4):
        # little endian load order
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
             ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2

        h1 ^= k1
        h1 = (h1 << 13) | ((h1 & 0xffffffff) >> 19)  # ROTL32(h1,13)
        h1 = h1 * 5 + 0xe6546b64

    # tail
    k1 = 0

    val = length & 0x03
    if val == 3:
        k1 = (data[roundedEnd + 2] & 0xff) << 16
    # fallthrough
    if val in [2, 3]:
        k1 |= (data[roundedEnd + 1] & 0xff) << 8
    # fallthrough
    if val in [1, 2, 3]:
        k1 |= data[roundedEnd] & 0xff
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1

    # finalization
    h1 ^= length

    # fmix(h1)
    h1 ^= ((h1 & 0xffffffff) >> 16)
    h1 *= 0x85ebca6b
    h1 ^= ((h1 & 0xffffffff) >> 13)
    h1 *= 0xc2b2ae35
    h1 ^= ((h1 & 0xffffffff) >> 16)

    return h1 & 0xffffffff


# tests
if __name__ == '__main__':
    filterload('mxaXRsBvD69jhE55TodZCUmLCDMYWAEcQn')
    a = filterload('mgDszfopY6fcda91t9kd4RrRM36YHmyeTd')
    b = filterload('mhKhbPztfWkptFx5o6htd9MYs4PQkg4mP2')
    c = filterload('cMxNY2aJ2RvmjZYJysdPh1NfF9HLqQRorPYoCYM9D6Rx61UA4bTT')

    # addresses to hash160
    address_arr = []
    data = ['mgDszfopY6fcda91t9kd4RrRM36YHmyeTd', 'mhKhbPztfWkptFx5o6htd9MYs4PQkg4mP2',
           'cMxNY2aJ2RvmjZYJysdPh1NfF9HLqQRorPYoCYM9D6Rx61UA4bTT']

    for a in data:
        if (a.startswith('m') or a.startswith('n')) and len(a) == 34:
            hash160 = bitcoin_address_to_hash160_sec(a, address_prefix=b'\x6f')
            address_arr.append(hash160)

    if not address_arr:
        exit(5)

    items_count = len(address_arr)
    for a in address_arr:
        print(filterload(a))

    exit()

    print(a, b, c)
    print(a & b)
    exit()

    t = {'mgDszfopY6fcda91t9kd4RrRM36YHmyeTd', 'mhKhbPztfWkptFx5o6htd9MYs4PQkg4mP2'}
    z = 50
    data_to_hash = 'mgDszfopY6fcda91t9kd4RrRM36YHmyeTd'
    for nHashNum in range(z):
        # nHashNum = hex("019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65")
        nIndex = filterload(nHashNum, data_to_hash)
        print(nIndex)
