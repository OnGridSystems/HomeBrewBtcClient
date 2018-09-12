import socket
import time

from pycoin.encoding import bitcoin_address_to_hash160_sec

import node.message as message
import node.msg_parser as msg_parser
import node.settings as settings
import node.version as version
from node.merkle import parse_merkleblock, PartialMerkleTree

MESSAGE_HEADER_SIZE = 24

MAX_HEADERS_RESULTS = 2000

MAXIMUM_VECTORS = 50000


class BitcoinProtocol:
    def __init__(self, ip, port=settings.DEFAULT_PORT, height=settings.STARTING_HEIGHT,
                 best_block=settings.STARTING_BLOCK):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((ip, port))
        self.buffer = bytes()
        self.HEIGHT = height
        self.BEST_BLOCK = best_block
        self.LAST_OP_TIME = int(time.time())
        self.REMOTE_NODE_VERSION = -1
        self.REMOTE_NODE_HEIGHT = -1
        self.HEADERS = []
        self.BLOCK_HEIGHT = height
        self.TST = {'headers': 0, 'block': 0}
        self.HEADERS_SENT = False
        self.HEADERS_RECEIVED = False
        self.LAST_HEADERS_RESULT = -1
        self.BLOCK_SENT = False
        self.BLOCK_RECEIVED = False
        self.BLOCKS_REQUESTED = 0
        self.GET_MAX_BLOCKS = False
        self.OFFSET = 0
        self.FILTERED_TXS = []
        self.MATCHED = []

        self.start_time = int(time.time())

        self.handshake()
        try:
            self.run()
        except (KeyboardInterrupt, SystemExit):
            print('Closing connection and exit...')
            self.connection.close()
            print('Work time', time.strftime("%H:%M:%S", time.gmtime(int(time.time()) - self.start_time)))
            print('Blocks received', len(self.HEADERS))
            print('Found', [tx['tx_id'] for tx in self.MATCHED])
            exit(0)

    def handshake(self):
        """
        Send handshake messages and check replay messages
        """
        self.connection.send(message.get_version(relay=False, start_height=self.HEIGHT))
        self.get_next_message()
        if msg_parser.get_command_name(self.buffer) != 'version':
            raise Exception('Protocol error')
        ver = msg_parser.get_version(self.buffer)
        # Check NODE_BLOOM flag
        if not (ver['version'] >= version.NO_BLOOM_VERSION and ver['services'] & 4 == 4):
            print('No bloom supported')
            exit(2)
        self.REMOTE_NODE_VERSION = ver['version']
        self.REMOTE_NODE_HEIGHT = ver['start_height']
        self.get_next_message()
        if msg_parser.get_command_name(self.buffer) != 'verack':
            raise Exception('Protocol error')
        # Accept version
        self.connection.send(message.get_verack())

    def setup_connection(self):
        """
        Send additional configuration messages to node
        """
        if self.REMOTE_NODE_VERSION >= version.SENDHEADERS_VERSION:
            self.connection.send(message.get_sendheaders())
        if self.REMOTE_NODE_VERSION >= version.NO_BLOOM_VERSION:
            adr_hashes = []
            for address in settings.WATCH_ADDRESSES:
                hash160 = bitcoin_address_to_hash160_sec(address, address_prefix=settings.PUB_PREFIX)
                adr_hashes.append(hash160)
            self.connection.send(message.get_filterload(adr_hashes, 0.0001, 0, 0))

    def read_from_socket(self, bytes_count):
        """
        :param bytes_count: Exact number of bytes to read
        :return: bytes read
        """
        buf = b''
        read_size = bytes_count
        while read_size > 0:
            buf += self.connection.recv(read_size)
            read_size = bytes_count - len(buf)
        return buf

    def socket_got_data(self):
        """
        Checks if there is data to read in the socket
        :return: Bool
        """
        import select
        readable, writable, exceptional = select.select([self.connection], [], [], 0.1)
        if self.connection in readable:
            return True
        else:
            print('no data to read')
            return False

    def get_next_message(self):
        """
        Reads single message from socket
        and put it into shared buffer
        """
        self.buffer = self.read_from_socket(MESSAGE_HEADER_SIZE)
        if self.buffer[0:4] != settings.MAGIC:
            raise ValueError('No magic bytes')
        size = int.from_bytes(self.buffer[16:20], byteorder='little')
        checksum = self.buffer[20:24]
        self.buffer += self.read_from_socket(size)
        if checksum != message.get_checksum(self.buffer[MESSAGE_HEADER_SIZE:MESSAGE_HEADER_SIZE + size]):
            raise ValueError('Checksum mismatch')

    def send_command(self):
        """
        Checks what command message can be sent and sent it
        """
        if self.send_getheaders():
            self.connection.send(message.get_headers([self.BEST_BLOCK]))
            self.LAST_OP_TIME = int(time.time())
            self.TST['headers'] = int(time.time())
            self.HEADERS_SENT = True
            print('sent', self.BEST_BLOCK)
        elif self.get_block():
            if self.GET_MAX_BLOCKS:
                # lets try request maximum blocks
                m = min(len(self.HEADERS) - 1, MAXIMUM_VECTORS)
                i = 0
                v = []
                while i < m:
                    v.append([3, self.HEADERS[i]['id']])
                    i += 1
                self.connection.send(message.get_getdata(v))
                self.BLOCKS_REQUESTED = m
                self.BLOCK_SENT = True
            else:
                # request single
                block_id = self.HEADERS[self.OFFSET]['id']
                print('sending', block_id)
                self.connection.send(message.get_getdata([[3, block_id]]))
                self.OFFSET += 1
                self.BLOCKS_REQUESTED = 1
                self.BLOCK_SENT = True

    def send_getheaders(self):
        """
        Checks can we send another getheaders message
        :return: Bool
        """
        if not self.HEADERS_SENT and not self.HEADERS_RECEIVED:
            return True
        if not self.HEADERS_SENT and self.HEADERS_RECEIVED and self.LAST_HEADERS_RESULT == MAX_HEADERS_RESULTS:
            return True
        elif not self.HEADERS_SENT and self.HEADERS_RECEIVED and self.LAST_HEADERS_RESULT < MAX_HEADERS_RESULTS:
            return False

        if self.HEADERS_SENT and not self.HEADERS_RECEIVED:
            if self.HEIGHT <= self.REMOTE_NODE_HEIGHT:
                if self.TST['headers'] + 30 >= int(time.time()):
                    return False
                else:
                    return True

    def get_block(self):
        """
        Checks can we request another block
        :return: Bool
        """
        if self.BLOCK_HEIGHT < self.HEIGHT:
            if self.HEADERS_SENT:
                return False
            if not self.BLOCK_SENT:
                return True

    def process_message(self):
        """
        Process last message in buffer and recalculates state variables
        """
        message_type = msg_parser.get_command_name(self.buffer)
        if message_type == 'headers':
            headers = msg_parser.get_headers(self.buffer)
            headers_count = len(headers)
            self.LAST_HEADERS_RESULT = headers_count
            if headers_count == 0:
                self.HEADERS_RECEIVED = True
                self.HEADERS_SENT = False
                return
            if headers_count > MAX_HEADERS_RESULTS:
                raise ValueError('ERROR: headers count received = ', headers_count)
            # Validate sequence
            last_header = None
            for header in headers:
                if last_header and header['prev_block'] != last_header:
                    print('non-continuous headers sequence')
                    raise ValueError('non-continuous headers sequence')
                last_header = header['id']
            # Add headers to chain
            if headers[0]['prev_block'] == self.BEST_BLOCK:
                self.HEADERS.extend(headers)
                self.BEST_BLOCK = self.HEADERS[-1]['id']
                self.HEIGHT += headers_count
            if headers_count < MAX_HEADERS_RESULTS:
                print('got {} headers'.format(headers_count))
                print(self.REMOTE_NODE_HEIGHT, self.HEIGHT)
            self.HEADERS_RECEIVED = True
            self.HEADERS_SENT = False
        elif message_type == 'merkleblock':
            self.BLOCK_HEIGHT += 1
            # print(self.buffer)
            data = parse_merkleblock(self.buffer[24:])
            # TODO move to PartialMerkleTree
            if data['total_transactions'] == 1 and len(data['hashes']) == 1 and data['hashes'][0] == data['merkle_root']:
                if data['flags'] == b'\x01':
                    self.FILTERED_TXS.extend(data['hases'])
                return
            pmt = PartialMerkleTree(data['total_transactions'], data['flags'], data['hashes'])
            assert pmt.get_merkle_root() == data['merkle_root'], 'merkle_root mismatch'
            if pmt.get_matches() is not None:
                self.FILTERED_TXS.extend(pmt.get_matches())
            else:
                self.BLOCK_SENT = False
                self.BLOCK_RECEIVED = True
        elif message_type == 'tx':
            tx, size = msg_parser.get_tx(self.buffer)
            print(tx['tx_id'])
            if tx['tx_id'] in self.FILTERED_TXS:
                self.FILTERED_TXS.remove(tx['tx_id'])
            else:
                raise ValueError('unknown transaction')
            if self.check_tx(tx):
                self.MATCHED.append(tx)
            if len(self.FILTERED_TXS) == 0:
                print('no tx left')
                print('Found', len(self.MATCHED))
                self.BLOCK_RECEIVED = True
                self.BLOCK_SENT = False
        elif message_type == 'ping':
            nonce = msg_parser.get_ping(self.buffer)
            pong = message.get_pong(nonce)
            self.connection.send(pong)
            print('ping received. pong was sent.')
        else:
            print('other command')
            print(self.buffer)

    def check_tx(self, tx):
        """
        Checks transaction inputs and outputs contains the addresses we need
        :param tx: Transaction
        :return: Bool
        """
        for txin in tx['tx_in']:
            if txin['address'] and txin['address'] in settings.WATCH_ADDRESSES:
                return True
        for txout in tx['tx_out']:
            if txout['address'] and txout['address'] in settings.WATCH_ADDRESSES:
                return True
        return False

    def finish(self):
        """
        Debug method
        Exit program when we reach the last known block
        """
        if self.REMOTE_NODE_HEIGHT == self.BLOCK_HEIGHT and len(self.FILTERED_TXS) == 0:
            print('Finishing')
            self.connection.send(message.get_filterclear())
            print('Work time', time.strftime("%H:%M:%S", time.gmtime(int(time.time()) - self.start_time)))
            print('Blocks received', len(self.HEADERS))
            print('Found', [tx['tx_id'] for tx in self.MATCHED])
            exit(0)

    def run(self):
        """
        Main loop
        Implements the protocol
        """
        self.setup_connection()
        while True:
            self.send_command()
            if self.socket_got_data():
                self.get_next_message()
                print('received', msg_parser.get_command_name(self.buffer))
                self.process_message()

                # This method for debug purpose only
                # it stop executing when all known blocks processed
                self.finish()


if __name__ == '__main__':
    # peer = peers.get_peer()
    peer = '192.168.254.242'
    cn = BitcoinProtocol(peer, settings.DEFAULT_PORT, 1381175,
                         '00000000000000ad3b482c63afb8137d06402585c757a380917c992be6861e8b')
