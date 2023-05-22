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

# class User:
#     def __init__(self):
        # public key
        # private key

        # generate public key

class mUser:
    def __init__(self):
        self.key_pair = self.generate_keys()
        self.public_key = self.key_pair[0]
        self.private_key = self.key_pair[1]
    # generate primes and ints automatically, compare with rsa from lib
    def generate_keys(self, prime1, prime2, int1, int2):
        p = prime1
        # prime checker
        q = prime2
        N = p*q
        phiN = (p-1)*(q-1) # pq 
        e = int1
        d = int2
        # modular checker
        ed = e*d 
        if (ed - 1) % phiN !=0:
            return 'invalid ed'
        pk = [e, N]
        sk = [d]
        return [pk, sk]
        
    def authenticate(self, message):
        # convert message into an integer algorithmically
        # raise encoded message to power of sk to encrypt
        pass
    def verify(self, ciphertext, sender_pk):
        # raise ciphertext to power of index 0 of sender's pk to decrypt
        pass
    def transaction_request(self, receiver_pk):
        # 
        pass
    def utxo_update(self, utxo_ledger):
        # 
        pass
    
    # UTXO ledger update
# node inherits from user, carries copy of blockchain consensus

# class Server:
# -- Circular queue mock, then network using sockets
# UTXO Model (ledger) keeping track of individuals balance (SQL)
class mServer:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.server = []
        self.front = 0
        self.rear = 0
        self.ledger = [] 

    def enqueue(self, item):
        self.server.append(item)
        self.rear += 1
        if self.front == 0:
            self.front += 1

    def dequeue(self):
        return self.server.pop(self.front)
    
    def check_empty(self):
        if self.front == self.rear + 1:
            return 'empty'

# class User:
# -- RSA Key Pair manual generation (temporary use lib)

# class Node(User):
# -- block reward system implementation