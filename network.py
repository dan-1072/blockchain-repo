import socket
import threading
import pickle
import enum

class MessageType(enum.Enum):
    '''defines incoming message types over the network, transaction or block, needed to handle serialisation differently'''
    TRANSACTION = 1
    BLOCK = 2
class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = []  # List of connected peers
        self.server = None
        self.miner_node = 0

    def start(self):
        '''initialises a server that listens for incoming messages: transactions from users and peer nodes, blocks from peer nodes'''
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # socket used to listen for incoming messages from peer nodes
        self.server.bind((self.host, self.port))
        self.server.listen()

        print(f"Node listening on {self.host}:{self.port}")

        while True: # always running until connection is broken
            client, address = self.server.accept() # block until a connection is established returning a new socket with the peer node
            print(f"Connection from {address}")

            peer_thread = threading.Thread(target=self.handle_peer, args=(client,)) # threads allow for efficient handling of multiple connections
            peer_thread.start()
            self.peers.append(client)

    def handle_peer(self, client):
        '''manages communication with a connected peer node'''
        while True:
            try:
                data = client.recv(1024) # receives data from connected peer with a max size of 1024 bytes
                if not data: # checks if the data is empty meaning the connection has been closed by the peer
                    break
                message = pickle.loads(data) # deserialise the serialised object
                self.handle_message(message) # message is handled by handle message method
            except Exception as e: # closes the connection if there is an error
                print(f"Error handling peer: {e}")
                break

    def handle_message(self, message):
        '''directs received messages to transaction handling or block handling'''
        if message['type'] == MessageType.TRANSACTION:
            self.handle_transaction(message['data'])
        elif message['type'] == MessageType.BLOCK:
            self.handle_block(message['data'])

    def handle_transaction(self, transaction):
        '''processes (validates) and adds transaction to the node's copy of the transaction pool'''
        # validate transaction
        # adds to transaction pool or rejects transaction
        print(f"Received transaction: {transaction}")

    def handle_block(self, block):
        ''' processes (validates) and adds block to the node's copy of the blockchain'''
        # validates block
        # adds to chain or rejects block
        print(f"Received block: {block}")


    def broadcast(self, message):
        '''broadcast a message to the peer nodes on the network that are listening'''
        serialised_message = pickle.dumps(message) # serialise the message for more efficient broadcasting 
        for peer in self.peers: # broadcast to all peer nodes on the network
            try:
                peer.send(serialised_message)
            except Exception as e:
                print(f"Error broadcasting to peer: {e}")

    def broadcast_transaction(self, transaction):
        '''broadcast a transaction to the peer nodes on the network through the broadcast method after specifying object type'''
        message = {'type': MessageType.TRANSACTION, 'data': transaction} # object type to serialise in broadcast method is transaction
        self.broadcast(message) # serialise and send the transaction

class MinerNode(Node):
    '''instances of this class can use the methods a typical node can use but they can also broadcast blocks to the network'''

    def initialise_miner(self):
        '''confirm a node is a miner node in the attributes of the node object'''
        self.mine_node = 1

    def broadcast_block(self, block):
        '''broadcast a block to the peer nodes on the network through the broadcast method after specifying object type'''
        message = {'type': MessageType.BLOCK, 'data': block}
        self.broadcast(message)

