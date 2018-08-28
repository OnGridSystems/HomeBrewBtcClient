import socket
import time

import msg_parser
import peers
import settings
import message
from ..BIP37 import bloom_messages as msg37

REMOTE_NODE_VERSION = -1
REMOTE_NODE_HEIGHT = -1
BUFFER_SIZE = 1024
BLOCK = settings.STARTING_BLOCK
BEST_BLOCK = None
BLOCKS = []
SYNCING = True

TX_POOL = []
BLOCK_POOL = []
FILTERED_BLOCK_POOL = []

MATCHES = []
HEIGHT = settings.STARTING_HEIGHT
RAW_BLOCKS = []
LOST_BLOCKS = []
CHUNK_SIZE = 0
HEADERS = {}

HEADERS_CHAIN = []
QUEUE = []
OFFSET = 0
WAIT_TIME = 15000
HEADERS_SENT_TIME = 0
INV_BLOCKS = []

CHECK_POINT = False
BLOCKS_REQ_COUNT = 10
REQ_BLOCKS = []
WAIT_FOR_BLOCK = False
HEADERS_SENT = False
HEADERS_RECEIVED = False

HEIGHT_REACHED = False
MAX_HEADERS_RESULTS = 2000


def handshake(sock):
    # Send our version to remote node
    sock.send(message.get_version(version=70012, relay=False, start_height=0))
    buffer = sock.recv(BUFFER_SIZE)
    # If got some errors in our version
    # Get reject message
    if buffer.startswith(b'reject'):
        raise Exception('version rejected')
    # Node should send version, verack
    # Check for version
    while msg_parser.no_full_message(buffer):
        buffer += sock.recv(BUFFER_SIZE)

    node_ver = msg_parser.get_message(buffer)
    print(node_ver)
    ver = msg_parser.get_version(node_ver)
    print(ver)
    print('services', ver['services'])
    if not (ver['version'] >= 70011 and ver['services'] & 4 == 4):
        print('no bloom supported')
        exit(1)
    # print(serialize.version(msg_parser.get_version(node_ver)))
    start_height = ver['start_height']
    buffer = buffer[len(node_ver):]

    while msg_parser.no_full_message(buffer):
        buffer += sock.recv(BUFFER_SIZE)

    if msg_parser.get_command_name(node_ver) != 'version':
        raise Exception('non version message')
    node_verack = msg_parser.get_message(buffer)
    buffer = buffer[len(node_verack):]
    if msg_parser.get_command_name(node_verack) != 'verack':
        raise Exception('non verack message')
    # Send verack to confirm handshake
    sock.send(message.get_verack())
    return buffer, start_height


def connect(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    return sock


if __name__ == '__main__':

    BLOCK = '0000000000000073ab554115f99be85a0fd3198e60bfb05a095f57259f4f070f'
    HEIGHT = 1410434
    QUEUE = [BLOCK]
    # BEST_BLOCK = settings.GENESIS_BLOCK.lower()
    BEST_BLOCK = BLOCK

    # SPV

    bloom = msg37.get_filterload()
    # bloom = msg37.get_filterclear()

    peer = peers.get_peer()
    port = settings.DEFAULT_PORT

    print('Connect to node {peer}:{port}'.format(peer=peer, port=port))
    sock = connect(peer, port)
    print('Do handshake')
    data, REMOTE_NODE_HEIGHT = handshake(sock)
    print('NODE_HEIGHT', REMOTE_NODE_VERSION)
    print('Handshake successful')
    if len(data) > -1:
        print('data', data)

    sock.send(bloom)
    mempool = message.get_mempool()
    sock.send(mempool)
    print('bloom and mempool sended')

    # sendheaders if available
    if REMOTE_NODE_VERSION >= 70012 or True:
        print('sending command')
        sendheaders = message.get_sendheaders()
        sock.send(sendheaders)

    HEIGHT = 0
    # BLOCK = settings.GENESIS_BLOCK
    getheaders = message.get_headers([BLOCK])
    sock.send(getheaders)

    watch_time1 = int(time.time())

    while True:

        if HEIGHT_REACHED:
            print('HEIGHT_REACHED')
            print('time passed', int(time.time()) - watch_time1)

        if HEADERS_SENT and HEADERS_SENT_TIME + WAIT_TIME <= int(time.time()):
            print('retry')
            HEADERS_SENT = False

        print('HEADERS_SENT', HEADERS_SENT)
        if HEADERS_CHAIN and HEADERS_CHAIN[-1]['id'] == BEST_BLOCK and not HEADERS_SENT:
            getheaders = message.get_headers([BEST_BLOCK])
            print('sendheaders from while')
            sock.send(getheaders)
            HEADERS_SENT = True
            HEADERS_SENT_TIME = int(time.time())

        while msg_parser.no_full_message(data):
            data += sock.recv(BUFFER_SIZE)

        command = msg_parser.get_message(data)
        data = data[len(command):]

        name = msg_parser.get_command_name(command)
        print(name)

        # INV
        if name == 'inv':
            vectors = msg_parser.get_inv(command)
            print('Received inv. Objects: {obj} Tx: {tx} Blocks: {blk} Filtered {filtered}'.format(obj=vectors[0],
                                                                                                   tx=sum(
                                                                                                       t[0] == 1 for t
                                                                                                       in vectors[1:]),
                                                                                                   blk=sum(
                                                                                                       t[0] == 2 for t
                                                                                                       in vectors[1:]),
                                                                                                   filtered=sum(
                                                                                                       t[0] == 3 for t
                                                                                                       in vectors[1:])))

            for tx in [t[1] for t in vectors[1:] if t[0] == 1]:
                TX_POOL.append(tx)

            for block in [t[1] for t in vectors[1:] if t[0] == 2]:
                BLOCK_POOL.append(block)

                # request merkle block
                vectors = [3, block]
                getdata = message.get_getdata([vectors])
                sock.send(getdata)
                print('filtered requested')

            for filtered_block in [t[1] for t in vectors[1:] if t[0] == 3]:
                FILTERED_BLOCK_POOL.append(filtered_block)

            if sum(t[0] == 1 for t in vectors[1:]):
                ls = [x[1] for x in vectors[1:] if x[0] == 1]
                print(ls)


        # PING
        elif name == 'ping':
            nonce = msg_parser.get_ping(command)
            pong = message.get_pong(nonce)
            sock.send(pong)
            print('ping received. pong was sent.')

        # ADDR
        elif name == 'addr':
            addresses = msg_parser.get_addr(command)
            print('addr', addresses, end='')
            print()

        # HEADERS
        elif name == 'headers':
            # Remember all headers
            headers = msg_parser.get_headers(command)

            print('headers received')

            if not headers:
                print('zero headers received')
                continue

            if len(headers) > MAX_HEADERS_RESULTS:
                print('ERROR: headers count received = ', len(headers))

            # process headers
            # validate
            last_header = None
            for header in headers:
                if last_header and header['prev_block'] != last_header:
                    print('non-continuous headers sequence')
                    raise ValueError('non-continuous headers sequence')
                last_header = header['id']

            # // If we don't have the last header, then they'll have given us
            # // something new (if these headers are valid).
            # if (!LookupBlockIndex(hashLastBlock)) {
            #     received_new_header = true;
            # }

            # Add headers to chain
            if headers[0]['prev_block'] == BEST_BLOCK:
                HEADERS_CHAIN.extend(headers)
                BEST_BLOCK = HEADERS_CHAIN[-1]['id']
                HEIGHT += len(headers)

            if HEIGHT >= REMOTE_NODE_HEIGHT:
                HEIGHT_REACHED = True

            print('received {count} headers'.format(count=len(headers)))

            if len(HEADERS_CHAIN) != len(set([t['id'] for t in HEADERS_CHAIN])):
                raise ValueError('mismatch!!!')

            if len(headers) < MAX_HEADERS_RESULTS:
                # 3 = filtered block
                vectors = [3, BEST_BLOCK]
                getdata = message.get_getdata([vectors])
                sock.send(getdata)
                print('filtered requested')

        # BLOCK
        elif name == 'block':

            print('block', command)
            print('block received ', end='')
            block = msg_parser.get_block(command)
            print(block['block_id'], block['prev_block'])

            print('CHECK_POINT', CHECK_POINT)
            print('WAIT_FOR_BLOCK', WAIT_FOR_BLOCK)
            if block['block_id'] == REQ_BLOCKS[0]['id']:
                print('Removed block', REQ_BLOCKS[0])
                REQ_BLOCKS = REQ_BLOCKS[1:]
                BLOCKS.append(block)
                HEIGHT += 1
            else:
                print('!!!WRONG BLOCK!!!')
                print(REQ_BLOCKS)
                print(block)
                exit(1)

            if BLOCKS[-1]['block_id'] == HDR_CHAIN[-1]['id']:
                CHECK_POINT = False
                QUEUE = [HDR_CHAIN[-1]['id']]
                print('Check point!!!!!!!!!!')

            if len(BLOCKS) == BLOCKS_REQ_COUNT:
                for block in BLOCKS:
                    txs = block['txns']
                    # for tx logging
                    log_txs(block['block_id'], txs)

                    TX_POOL.extend(process_txs(txs))
                WAIT_FOR_BLOCK = False
                print('TX_POOL is', len(TX_POOL), TX_POOL)
                BLOCKS.clear()
                # HEIGHT
                print('Passed {} / {}'.format(HEIGHT, NODE_HEIGHT))

        # TX
        elif name == 'tx':
            tx = msg_parser.get_tx(command)
            print(tx)

        # ALERT
        elif name == 'alert':
            print(command)

        # VERSION
        elif name == 'version':
            ver = msg_parser.get_version(command)
            print(ver)

        elif name == 'merkleblock':
            print('MERKLEBLOCK received')
            print(command)

        # OTHER
        else:
            print('Something new!')
            print(command)
