# Network 	Magic value 	Sent over wire as
# main 	    0xD9B4BEF9 	    F9 BE B4 D9
# testnet 	0xDAB5BFFA 	    FA BF B5 DA
# testnet3 	0x0709110B 	    0B 11 09 07
# namecoin 	0xFEB4BEF9 	    F9 BE B4 FE
DEFAULTS_PARAMS = {
    'main': {
        'MAGIC_BYTES': b'\xF9\xBE\xB4\xD9',
        'PUBKEY_PREFIX': b'\x00',
        'DNS_SEED': ['seed.bitcoin.sipa.be', 'dnsseed.bitcoin.dashjr.org', 'bitseed.xf2.org', 'dnsseed.bluematt.me'],
        'DEFAULT_PORT': 8333,
        'GENESIS_BLOCK': '000000000019D6689C085AE165831E934FF763AE46A2A6C172B3F1B60A8CE26F',
    },
    'testnet': {
        'MAGIC_BYTES': b'\x0B\x11\x09\x07',
        'PUBKEY_PREFIX': b'\x6F',
        'DNS_SEED': ['testnet-seed.bitcoin.jonasschnelli.ch', 'seed.tbtc.petertodd.org',
                     'seed.testnet.bitcoin.sprovoost.nl',
                     'testnet-seed.bluematt.me'],
        'DEFAULT_PORT': 18333,
        'GENESIS_BLOCK': '000000000933EA01AD0EE984209779BAAEC3CED90FA3F408719526F8D77F4943',
    }
}
