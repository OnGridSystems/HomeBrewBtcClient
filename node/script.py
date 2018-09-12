import binascii

from pycoin import encoding
from pycoin.tx.script import tools

import node.settings as settings


def pkscript2addr(pkscript):
    if type(pkscript) is not bytes:
        pkscript = binascii.unhexlify(pkscript)
    # Pay-to-PubkeyHash
    if pkscript[:2] == b'\x76\xa9' and pkscript[-2:] == b'\x88\xac':
        ln = pkscript[2]
        pubkeyhash = pkscript[3:3 + ln]
        data = settings.PUB_PREFIX + pubkeyhash
        res = encoding.b2a_hashed_base58(data)
        return res
    # Pay-to-Script-Hash
    elif False:
        return 'TODO'
    # OP_RETURN
    elif pkscript[0] == b'\x6a':
        return 'null'
    return False


def scriptsig2adddr(scriptsig):
    if type(scriptsig) is not bytes:
        scriptsig = binascii.unhexlify(scriptsig)
    pos = 0
    ln = scriptsig[pos]
    pos += 1
    sig = sigscript[pos:pos + ln]
    pos += ln
    ln = scriptsig[pos]
    pos += 1
    pubkey = scriptsig[pos:pos + ln:]
    pubkeyhash = encoding.hash160(pubkey)
    r = encoding.b2a_hashed_base58(settings.PUB_PREFIX + pubkeyhash)
    return r


def to_codes(script):
    return tools.opcode_list(script)


if __name__ == '__main__':
    pk_script = binascii.unhexlify(b'76a9143b0d8c82b550cd4878749cd02259822c00af78a788ac')

    address = pkscript2addr(pk_script)
    assert address == 'mkuCPmGF9wiSNgw74bPf8EaKQmbVzMaVr1', 'Wrong hash'
    print(address)

    sigscript = binascii.unhexlify('473044022049d3fd02900625abc0fd10d95c3b3f060a542f7c411e121ab21a73fa5c1959970220052a15ca5324cbf4292d86a994267df2e439e1be54d5d6bb10f285961618c8fe012102eb2c0538006d96d9ffc1fd6bb692a2ec6acbb952a8b76e571207d6dfc306c589')
    address = scriptsig2adddr(sigscript)
    assert address == 'mqXPVSc3BACV3Dt5TDQyjZ756F7s4uZmHV', 'Wrong hash'
    print(address)
