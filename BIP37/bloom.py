from math import log

# (36,000: selected as it represents a filter of 20,000 items with false
# positive rate of < 0.1% or 10,000 items and a false positive rate of < 0.0001%).
MAX_BLOOM_FILTER_SIZE = 36000  # bytes
MAX_HASH_FUNCS = 50

LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
LN2 = 0.6931471805599453094172321214581765680755001343602552


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


class BloomFilter:
    def __init__(self, element_count, false_positive_rate, tweak):
        self.nElements = element_count
        self.nFPRate = false_positive_rate
        self.nTweak = tweak
        filter_size = int(min((-1 / LN2SQUARED * self.nElements * log(self.nFPRate)), MAX_BLOOM_FILTER_SIZE * 8) / 8)
        self.hash_func_num = int(min((filter_size * 8 / self.nElements * LN2), MAX_HASH_FUNCS))
        self.filter_bytes = bytearray(filter_size)
        self.bit_count = 8 * filter_size

    # data is hash160 address
    def insert(self, data):
        for hash_index in range(self.hash_func_num):
            seed = hash_index * 0xFBA4C795 + self.nTweak
            bit_index = murmur3(data, seed=seed) % self.bit_count
            # set bit
            if bit_index > self.bit_count:
                raise ValueError('bit index out of range')
            byte_index, bit_index = divmod(bit_index, 8)
            self.filter_bytes[byte_index] |= 1 << (7 - bit_index)

    def contains(self, item):
        for hash_index in range(self.hash_func_num):
            seed = hash_index * 0xFBA4C795 + self.nTweak
            bit_index = murmur3(item, seed=seed) % self.bit_count
            if bit_index > self.bit_count:
                raise ValueError('bit index out of range')
            byte_index, bit_index = divmod(bit_index, 8)
            if not self.filter_bytes[byte_index] & 1 << (7 - bit_index):
                return False
        return True

    def get_filter(self):
        return self.filter_bytes

    def get_filter_params(self):
        return self.filter_bytes, self.hash_func_num, self.nTweak


if __name__ == '__main__':
    h = b'\x07\xbdw\x17\x87.\x19\x96h\x8e\x14\xcf#\r\xc2\xbb>Y\xbf\xde'
    f = BloomFilter(1, 0.0001, 0)
    f.insert(h)
    assert bytes(f.get_filter()) == b'\rZ', 'Filter mismatch'

    # CBloomFilter filter(3, 0.01, 0, BLOOM_UPDATE_ALL)
    # filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    # BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't
    # contain just-inserted object!");
    # // One bit different in first byte
    # BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter
    # contains something it shouldn't!");
    f = BloomFilter(3, 0.01, 0)
    f.insert(b"\x99\x10\x8a\xd8\xed\x9b\xb6'M9\x80\xba\xb5\xa8\\\x04\x8f\tP\xc8")
    assert f.contains(b"\x99\x10\x8a\xd8\xed\x9b\xb6'M9\x80\xba\xb5\xa8\\\x04\x8f\tP\xc8"), "Bloom filter doesn't contain just-inserted object!"
    assert not f.contains(b"\x19\x10\x8a\xd8\xed\x9b\xb6'M9\x80\xba\xb5\xa8\\\x04\x8f\tP\xc8"), "Bloom filter contains something it shouldn't!"

    # "b5a2c786d9ef4658287ced5914b37a1b4aa32eee"
    f.insert(b'\xb5\xa2\xc7\x86\xd9\xefFX(|\xedY\x14\xb3z\x1bJ\xa3.\xee')
    assert f.contains(b'\xb5\xa2\xc7\x86\xd9\xefFX(|\xedY\x14\xb3z\x1bJ\xa3.\xee'), "Bloom filter doesn't contain just-inserted object!"

    # "b9300670b4c5366e95b2699e8b18bc75e5f729c5"
    f.insert(b'\xb90\x06p\xb4\xc56n\x95\xb2i\x9e\x8b\x18\xbcu\xe5\xf7)\xc5')
    assert f.contains(b'\xb90\x06p\xb4\xc56n\x95\xb2i\x9e\x8b\x18\xbcu\xe5\xf7)\xc5'), "Bloom filter doesn't contain just-inserted object!"
