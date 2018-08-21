import binascii
import hashlib
import random
import secrets

from .dictionary import eng_dict


class BIP39:

    def __init__(self, ent=None):
        self.entropy = ent or self.gen_ran_entropy()

    @staticmethod
    def gen_ran_entropy():
        """
        Used to generate random entropy by python's lib
        Cryptographically Secure Pseudo-Random Generator Library
        """
        rand_bits = [8, 10, 12, 14, 16]
        entropy = secrets.token_hex(rand_bits[random.randint(0, 4)])
        return hashlib.sha256(entropy.encode('utf-8')).digest()

    @property
    def to_mnemonic(self):
        """
        Getting a mnemonic phrase from entropy
        :return: List of mnemonic phrase
        """
        if len(self.entropy) not in [16, 20, 24, 28, 32]:
            raise ValueError(
                'Entropy length should be one of the following: [16, 20, 24, 28, 32], but it is not (%d).' % len(
                    self.entropy))
        entropy_hash = hashlib.sha256(self.entropy).hexdigest()
        entropy_chk_sum = bin(int(binascii.hexlify(self.entropy), 16))[2:].zfill(len(self.entropy) * 8) + \
                          bin(int(entropy_hash, 16))[2:].zfill(256)[:len(self.entropy) * 8 // 32]
        mnemonic_phrase = []
        for i in range(len(entropy_chk_sum) // 11):
            idx = int(entropy_chk_sum[i * 11:(i + 1) * 11], 2)
            mnemonic_phrase.append(eng_dict[idx])
        return mnemonic_phrase

    @property
    def seed(self):
        """
        Getting a seed from entropy
        :return: Seed (hex)
        """
        data = hashlib.sha3_512(self.entropy)
        return data.hexdigest()
