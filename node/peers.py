from multiprocessing.dummy import Pool
import random
import socket
import time

import settings
from contextlib import closing


def lookup():
    peers = set()
    for hostname in settings.DNS_SEED:
        try:
            address_info = socket.getaddrinfo(hostname, settings.DEFAULT_PORT, family=socket.AF_INET)
        except:
            continue
        results = set(a[-1][0] for a in address_info)
        peers.update(results)
    return check_peers(peers)


def check_peer(peer, port=settings.DEFAULT_PORT):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(1)
        connected = sock.connect_ex((peer, port)) == 0
    return connected


def check_peer_2(peer):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(1)
        connected = peer if sock.connect_ex((peer, settings.DEFAULT_PORT)) == 0 else None
    return connected


def check_peers(peers):
    pool = Pool(len(peers))
    result = pool.map(check_peer_2, list(peers))
    pool.close()
    pool.join()
    active_peers = set(result)
    if None in active_peers:
        active_peers.remove(None)
    return active_peers


def init_peer_list():
    peers = lookup()
    timestamp = int(time.time())
    for peer in peers:
        settings.PEER_LIST[peer] = timestamp


# Fill peers and return random one
def get_peer():
    if len(settings.PEER_LIST) == 0:
        init_peer_list()
    secure_random = random.SystemRandom()
    return secure_random.choice(list(settings.PEER_LIST.keys()))


if __name__ == '__main__':
    print(lookup())
