import binascii
import hashlib
import random
import secrets
from dict import eng_dict


class BIP39:

    def __init__(self, ent=None):
        self.entropy = ent or self.gen_ran_entropy()
        self.gen_ran_entropy()


    # Used to generate random entropy by python's lib
    #(Cryptographically Secure Pseudo-Random Generator Library)
    def gen_ran_entropy(self):
        rand_bits = [8, 10, 12, 14, 16]
        entropy = secrets.token_hex(rand_bits[random.randint(0, 4)])
        self.entropy = hashlib.sha256(entropy.encode('utf-8')).digest()

    #Getting a mnemonic phrase from entropy
    @property
    def to_mnemonic(self):
        ent = self.entropy
        if len(ent) not in [16, 20, 24, 28, 32]:
            raise ValueError(
                'Entropy length should be one of the following: [16, 20, 24, 28, 32], but it is not (%d).' % len(
                    ent))
        entropy_hash = hashlib.sha256(ent).hexdigest()
        entropy_chk_sum = bin(int(binascii.hexlify(ent), 16))[2:].zfill(len(ent) * 8) + \
                          bin(int(entropy_hash, 16))[2:].zfill(256)[:len(ent) * 8 // 32]
        mnemonic_phrase = []
        for i in range(len(entropy_chk_sum) // 11):
            idx = int(entropy_chk_sum[i * 11:(i + 1) * 11], 2)
            mnemonic_phrase.append(eng_dict[idx])
        return mnemonic_phrase

    #Getting a seed from entropy
    @property
    def seed(self):
        data = hashlib.sha3_512(self.entropy)
        return data.hexdigest()



