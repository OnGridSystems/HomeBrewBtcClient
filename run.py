import node.peers as peers
import node.settings as settings
from node.protocol import BitcoinProtocol

if __name__ == '__main__':
    # Redefine addresses
    settings.WATCH_ADDRESSES.clear()
    settings.WATCH_ADDRESSES.add('mkgLkoMxmLkJLmhfwUwtpdD3ku6Auhf1Xg')

    peer = peers.get_peer()
    # peer = '192.168.0.1'
    SPV_protocol = BitcoinProtocol(peer, settings.DEFAULT_PORT, 1413111,
                                   '00000000000132389c022d11eb14da4448a44df02ebed91facb5ec5b0350898d')
