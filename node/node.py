import socket
import time

import msg_parser
import peers
import settings
import message

BUFFER_SIZE = 1024
BLOCK = settings.STARTING_BLOCK
BLOCKS = []
SYNCING = True
TX_POOL = []
MATCHES = []
HEIGHT = settings.STARTING_HEIGHT
RAW_BLOCKS = []
LOST_BLOCKS = []
CHUNK_SIZE = 0
HEADERS = {}
NODE_HEIGHT = -1
HDR_CHAIN = []
QUEUE = []
OFFSET = 0
WAIT_TIME = 15
HEADERS_SENT_TIME = 0
INV_BLOCKS = []

CHECK_POINT = False
BLOCKS_REQ_COUNT = 10
REQ_BLOCKS = []
WAIT_FOR_BLOCK = False
HEADERS_SENT = False
HEADERS_RECEIVED = False


# Build chain of block references each other
def build_chain(last_block, headers_dict):
    rev_hdrs = {v['prev_block']: v for v in headers_dict.values()}
    while last_block in rev_hdrs.keys():
        blk = rev_hdrs.pop(last_block)
        HDR_CHAIN.append(headers_dict.pop(blk['id']))
        last_block = blk['id']
    return last_block, headers_dict


# Find tx with given addresses
def process_txs(txns):
    result = []
    while txns:
        tx = txns.pop(0)
        # DEBUG
        # if tx['tx_id'] == 'e6d6f489a29eb5a87a05b7471689dbb144efaf07e6bbc0b5a77eaf8ef4742d0a':
        #     print('!!!_1')
        # if tx['tx_id'] == 'b815cfb6c8c48a1f8de1bc25fee52931dc271e69fc000c9f7ecc71c93de3ddc2':
        #     print('!!!_2')

        for txin in tx['tx_in']:
            if txin['address'] and txin['address'] in settings.WATCH_ADDRESSES:
                result.append(tx)
                break
        for txout in tx['tx_out']:
            if txout['address'] and txout['address'] in settings.WATCH_ADDRESSES:
                result.append(tx)
                break
    return result


def handshake(sock):
    # Send our version to remote node
    sock.send(message.get_version())
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


# Testcase
if __name__ == '__main__':

    BLOCK = '00000000000000161e0a215662a86eb9ac7b3d71e341ed51fded1b9543f4f717'
    # mgDszfopY6fcda91t9kd4RrRM36YHmyeTd
    # BLOCK = '00000000000000ad3b482c63afb8137d06402585c757a380917c992be6861e8b'
    # mhKhbPztfWkptFx5o6htd9MYs4PQkg4mP2
    # BLOCK = '000000000000003c1a83f0a57e899ab7656f1a920e3706167dbf50c9d798a3d0'
    HEIGHT = 1383547
    QUEUE = [BLOCK]

    peer = peers.get_peer()
    port = settings.DEFAULT_PORT

    print('Connect to node {peer}:{port}'.format(peer=peer, port=port))
    sock = connect(peer, port)
    print('Do handshake')
    data, NODE_HEIGHT = handshake(sock)
    print('NODE_HEIGHT', NODE_HEIGHT)
    print('Handshake successful')
    if len(data) > -1:
        print('data', data)

    REQUEST_HEADERS_MESSAGE = None

    # Main cycle
    while True:
        # Initial download
        ##########################################
        # Request headers from last known block
        # At start we know at least one block hash
        # Genesis constant or settings specified
        # This one single hash in the QUEUE list
        if QUEUE:
            REQUEST_HEADERS_MESSAGE = message.get_headers(QUEUE)
            sock.send(REQUEST_HEADERS_MESSAGE)
            print('Send getheaders {}'.format(QUEUE))
            HEADERS_SENT = True
            HEADERS_RECEIVED = False
            QUEUE.clear()

        # Check wait timeout
        if HEADERS_SENT and not HEADERS_RECEIVED:
            # if WAIT_FOR_BLOCK and not CHECK_POINT:
            if HEADERS_SENT_TIME + WAIT_TIME < int(time.time()):
                print('Repeat headers')
                sock.send(REQUEST_HEADERS_MESSAGE)
                HEADERS_SENT_TIME = int(time.time())

        # Request for block if meet requirements
        if CHECK_POINT and not WAIT_FOR_BLOCK:
            print('Requesting for blocks')
            if OFFSET + BLOCKS_REQ_COUNT < len(HDR_CHAIN):
                REQ_BLOCKS = HDR_CHAIN[OFFSET:OFFSET + BLOCKS_REQ_COUNT]
                OFFSET = OFFSET + BLOCKS_REQ_COUNT
            elif len(HDR_CHAIN) != OFFSET:
                REQ_BLOCKS = HDR_CHAIN[OFFSET:]
                OFFSET = len(HDR_CHAIN) - 1
            print('Requested {} blocks: {}'.format(len(REQ_BLOCKS), REQ_BLOCKS))
            print('From {} to {}'.format(OFFSET, BLOCKS_REQ_COUNT))
            vectors = [[2, b['id']] for b in REQ_BLOCKS]
            req_blocks_mes = message.get_getdata(vectors)
            sock.send(req_blocks_mes)
            print(req_blocks_mes)
            WAIT_FOR_BLOCK = True
            HEADERS_SENT_TIME = int(time.time())

        read = 1
        print('reading ', end='')
        while msg_parser.no_full_message(data):
            read += 1
            data += sock.recv(BUFFER_SIZE)
        print('read', read)

        command = msg_parser.get_message(data)
        data = data[len(command):]

        name = msg_parser.get_command_name(command)
        print(name)

        # INV
        if name == 'inv':
            vectors = msg_parser.get_inv(command)
            print('Received inv. Objects: {obj} Tx: {tx} Blocks: {blk}'.format(obj=vectors[0],
                                                                               tx=sum(t[0] == 1 for t in vectors[1:]),
                                                                               blk=sum(t[0] == 2 for t in vectors[1:])))

            # save inv blocks for history
            if sum(t[0] == 2 for t in vectors[1:]):
                INV_BLOCKS.extend([x[1] for x in vectors[1:] if x[0] == 2])
                print('INV_BLOCKS', INV_BLOCKS)

            for blk_hash in INV_BLOCKS:
                if blk_hash in HDR_CHAIN:
                    INV_BLOCKS.remove(blk_hash)

            if not QUEUE and CHECK_POINT and len(BLOCKS) <= len(HDR_CHAIN) and INV_BLOCKS and not HEADERS_SENT:
                QUEUE.extend(INV_BLOCKS)

            # TODO find out when node start send inv after handshake

            # Request all
            continue
            # Request only blocks
            if len(BLOCKS) == 0 and sum(t[0] == 2 for t in vectors[1:]) > 0:
                only_blocks = [x for x in vectors[1:] if x[0] == 2]
                BLOCKS.extend(only_blocks)
                CHUNK_SIZE = len(only_blocks)
            if BLOCKS:
                # block = BLOCKS.pop(0)
                # getdata = message.get_getdata([block])
                getdata = message.get_getdata(BLOCKS)
                sock.send(getdata)

        # PING
        elif name == 'ping':
            nonce = msg_parser.get_ping(command)
            pong = message.get_pong(nonce)
            sock.send(pong)
            print('ping received. pong was sent.')

        # ADDR
        elif name == 'addr':
            addresses = msg_parser.get_addr(command)
            print(addresses, end='')
            print()

        # HEADERS
        elif name == 'headers':
            # Remember all headers in dict
            headers = msg_parser.get_headers(command)

            if HEADERS_SENT:
                HEADERS_RECEIVED = True
                HEADERS_SENT = False

            if not headers:
                CHECK_POINT = True
                print('Get zero headers ', end='')
                print(CHECK_POINT)
                continue

            print('Headers received {}'.format(headers))
            for h in headers:
                if h['id'] not in HEADERS.keys():
                    HEADERS[h['id']] = h
            if sum(h['prev_block'] == BLOCK for h in HEADERS.values()):
                BLOCK, HEADERS = build_chain(BLOCK, HEADERS)
                if not QUEUE:
                    QUEUE = [HDR_CHAIN[-1]['id']]

            # Clear inv
            for blk_hash in INV_BLOCKS:
                if blk_hash in HDR_CHAIN:
                    INV_BLOCKS.remove(blk_hash)

        # BLOCK
        elif name == 'block':
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
                    TX_POOL.extend(process_txs(txs))
                WAIT_FOR_BLOCK = False
                print('TX_POOL is', len(TX_POOL), TX_POOL)
                BLOCKS.clear()
                # HEIGHT
                print('Passed {} / {}'.format(HEIGHT, NODE_HEIGHT))

            continue

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

        # OTHER
        else:
            print('Something new!')
            print(command)
