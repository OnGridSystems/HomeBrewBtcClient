import hashlib
import struct
from pycoin.encoding import bitcoin_address_to_hash160_sec
from .bloom import BloomFilter

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
def filterload(items, fp_rate, tweak, flags, max_items=None):
    # items, tweak, max_items=None
    if type(items) is not list:
        items = [items]
    if max_items is None:
        n_elements = len(items)
    else:
        n_elements = max_items

    f = BloomFilter(n_elements, fp_rate, tweak)
    for item in items:
        f.insert(item)

    filter, num_hash_funcs, tweak = f.get_filter_params()
    payload = filter + struct.pack('<I', num_hash_funcs) + struct.pack('<I', tweak) + flags

    return make(b'\x0B\x11\x09\x07', 'filterload', payload)


def get_filterload():
    # payload = b'\x02\xb0Z\x0b\x00\x00\x00\x00\x00\x00\x00\x00'
    payload = b'\x02B\x9d\x0b\x00\x00\x00\x00\x00\x00\x00\x00'
    return make(b'\x0B\x11\x09\x07', 'filterload', payload)


def get_filterclear():
    return make(b'\x0B\x11\x09\x07', 'filterclear', b'')


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

    t = {'mgDszfopY6fcda91t9kd4RrRM36YHmyeTd', 'mhKhbPztfWkptFx5o6htd9MYs4PQkg4mP2'}
