"""
BIP44 parameters to derive keys:
Derived key base58:
Private key (WIF, compressed):
P2PKH address:
Pay to Script Hash (P2SH) address:
SegWit P2SH-P2WPKH address:
SegWit bech32 P2WPKH address:
"""
import binascii
import hashlib
from datetime import datetime

from BIP039.bip039 import BIP39


class BIP44:

    def __init__(self):
        pass

    def generate_child_id(self):
        now = datetime.now()
        seconds_since_midnight = (now - now.replace(
            hour=0, minute=0, second=0, microsecond=0)).total_seconds()
        return int((int(now.strftime(
            '%y%m%d')) + seconds_since_midnight * 1000000) // 100)

    def get_master_private_key(self, seed):
        """
        Taking the left part of seed (left 256 bit)
        after that generate Master Private Key "m",
        which could be only 256 bits
        """
        seed = hashlib.sha256(seed.encode('utf-8')).digest()

        right_part = bin(int(binascii.hexlify(seed), 16))[2:].zfill(512)[256:]          #str type

    def get_master_public_key(self, master_private_key):
        """
        Generate Master public key "M", which could be only 264 bits
        """
        pass

    def get_master_chain_code(self, seed):
        pass



