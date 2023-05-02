from datetime import datetime
import hashlib

class Blockchain:
    def __init__(self):
        self.proof_of_work = '0' * 8
        self.chain = [self.genesis]
        self.genesis = Block(self, 0, 0)

    # def block_reward(self):
        # node class required

    def history(self):
        return self.chain

    def pow(self):
        return self.proof_of_work

class Block:
    def __init__(self, blockchain, data, previous_hash):
        self.blockchain = blockchain
        self.timestamp = datetime.now()
        self.index = len(blockchain) + 1
        if previous_hash==None:
            self.previous_hash = blockchain.history()[-1].prev_hash()
        elif previous_hash==0:
            self.previous_hash = previous_hash
        self.data = data
        self.nonce = 0
        self.dict_repr = {'timestamp': self.timestamp, 'previous hash': self.previous_hash, 'transactions': self.data, 'nonce': self.nonce}
        self.hash = self.get_hash()


    def __repr__(self):
        return f"{self.dict_repr}"
    
    def get_hash(self):
        hash = hashlib.sha256(self.__repr__())
        return hash

    def prev_hash(self):
        return self.previous_hash
    
    def mine(self):
        while self.hash[:8] != self.blockchain.pow():
            self.nonce += 1
            self.dict_repr = {'timestamp': self.timestamp, 'previous hash': self.previous_hash, 'transactions': self.data, 'nonce': self.nonce}
            self.hash = self.get_hash()

    # introduce proof-of-work variable later

    def genesis_block(self):
        self.previous_hash = 0
        self.data = 0


# class Server:
# -- Circular queue mock, then network using sockets

# class User:
# -- RSA Key Pair manual generation

# class Node(User):
# -- block reward system implementation
