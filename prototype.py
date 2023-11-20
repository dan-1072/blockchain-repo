import hashlib
from datetime import datetime
import math
import random
import time
import sys
sys.setrecursionlimit(10**6)

class RSA:
    def __init__(self, key_length=1024):
        self.key_length = key_length # desired length of keys (longer keys are more computationally intensive to crack)

    def is_prime(self, n, k=5):
        """Miller-Rabin primality test."""
        if n <= 1 or n % 2 == 0:
            return False
        if n == 2 or n == 3:
            return True

        # Write n as 2^r * d + 1
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # loop for trying different values of a
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_prime(self, bits):
        """Generate a random prime number with the specified number of bits."""
        while True: # generate random numbers until the number passes Miller-Rabin primality test
            num = random.getrandbits(bits)
            if self.is_prime(num):
                return num

    def egcd(self, a, b):
        """Extended Euclidean Algorithm for finding modular inverses."""
        if a == 0:
            return (b, 0, 1)
        else:
            g, x, y = self.egcd(b % a, a)
            return (g, y - (b // a) * x, x)

    def modinv(self, a, m):
        """Modular multiplicative inverse."""
        g, x, y = self.egcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist')
        else:
            return x % m

    def generate_keys(self):
        p = self.generate_prime(self.key_length // 2) # Generate two large random prime numbers
        q = self.generate_prime(self.key_length // 2)
        n = p * q# Compute n (modulus)
        phi = (p - 1) * (q - 1) # Compute totient (phi)
        e = 65537  # Choose public exponent (65537 is a Commonly used value in RSA)
        d = self.modinv(e, phi) # Compute private exponent d
        public_key = (e, n)# Public key (e, n)
        private_key = (d, n) # Private key (d, n)

        return public_key, private_key

    def encrypt(self, plaintext, d, n):
        '''encryption for signing transactions'''
        cipher_text = [pow(ord(char), d, n) for char in plaintext] # pow function is exponentiation
        return cipher_text

    def decrypt(self, cipher_text, e, n):
        '''decryption for verifying digital signatures'''
        plain_text = ''.join([chr(pow(char, e, n)) for char in cipher_text]) # pow function is exponentiation
        return plain_text

class Wallet:
    # public key
    # private key
    # balance
    def __init__(self):
        self.public_key = None
        self._private_key = None
        self.balance = 0

    def generate_keypair(self):
    # generate public and private keys
        self.public_key, self.private_key = RSA().generate_keys()

    def create_transaction(self, recipient_wallet, amount):
        recipient_pk = recipient_wallet.reveal_pk()
        transaction = Transaction(self.public_key, recipient_pk, amount, self.private_key) # automatically signs transaction
        return transaction
    
    def validate_transaction(self, broadcaster, digital_signature, transactionID):
    # check if user has sufficient funds, verify signature
        broadcaster_pk = broadcaster.public_key
        plain_text = ''.join([chr(pow(char, broadcaster_pk[0], broadcaster_pk[1])) for char in digital_signature]) # pow function is exponentiation
        if plain_text == transactionID:
            return True
        else:
            return False
        
    def reveal_pk(self):
        return self.public_key

    # check balance

class Transaction():

    def __init__(self, sender_pk, recipient_pk, amount, private_key):
        self.sender_pk = sender_pk
        self.recipient_pk = recipient_pk
        self.amount = amount
        self.timestamp = datetime.now().strftime("%H:%M:%S")
        self.transactionID = self.calculate_transactionID()
        self.digital_signature = self.sign_transaction(private_key)

    def calculate_transactionID(self):
        # Calculate hash of the transaction's contents to represent transaction when referenced on blockchain
        transaction_data = f"{self.sender_pk}{self.recipient_pk}{self.amount}{self.timestamp}"
        transactionID = hashlib.sha256(transaction_data.encode('utf-8')).hexdigest() # encoded -> hashed (binary) -> converted to hexadecimal
        return transactionID
    
    def sign_transaction(self, private_key): # encryption and decryption mathematics explained in doc
        '''encryption for signing transactions'''
        digital_signature = [pow(ord(char), private_key[0], private_key[1]) for char in self.transactionID] # pow function is exponentiation
        return digital_signature
    
    def validate_transaction(self):
        '''decryption for verifying digital signatures, and checking if user has sufficient funds'''
        # decrypt the encrypted transaction ID and compare to transaction ID of the transaction to see if decryption worked (keys are linked)
        decryption = ''.join([chr(pow(char, self.sender_pk[0], self.sender_pk[1])) for char in self.digital_signature]) # pow function is exponentiation
        if decryption == self.transactionID:
            return True
        else:
            return False
        
    def __repr__(self):
        return (
            f"Transaction(sender_pk={self.sender_pk}, "
            f"recipient_pk={self.recipient_pk}, "
            f"amount={self.amount}, "
            f"timestamp={self.timestamp}, "
            f"transactionID={self.transactionID}, "
            f"digital_signature={self.digital_signature})"
        )
    
class TransactionDatabase:
    pass


class ExampleDataset: # for testing merkle tree functionality and behaviour of transaction objects 
    def __init__(self, length):
        self.dataset = []
        self.length = length # desired length of example dataset

    def get_dataset(self):
        return self.dataset

    def data_gen(self): # generate single item of data (random integer in place of transactions)
            data = random.randint(0, 9)
            return data

    def set(self): # generate dataset 
        while len(self.dataset) < self.length:
            data = self.data_gen()
            self.dataset.append(data)
        return self.dataset
    
class TreeNode: # node class to store all transactions individually in nodes, merkle tree is made up of these nodes through aggregation
    def __init__(self, dataset):
        self.dataset = dataset
        self.node = []
        self.fill()
        self.content = self.node[0]
    
    def item_transfer(self): # transfer element out of dataset
        length = len(self.dataset)
        index = random.randint(0, length - 1)
        return self.dataset.pop(index)

    def fill(self): # take one element of data from dataset and form node (hashed)
        self.item = self.item_transfer() # pops (returns) random element out of dataset
        self.hash_input = f"{self.item}".encode("utf-8")
        self.hash = hashlib.sha256(self.hash_input).hexdigest()
        self.node.append(self.hash)

    def __repr__(self): # string representation of node
        return f"TreeNode(node_content={self.content})"

class MerkleTree: # allows for integrity checking of data (confirms data has not been tampered with, comparing datasets between nodes to check if they are the same faster, etc)
    # only root is stored on chain, efficient validation of integrity for comparisons
    def __init__(self, dataset):
        self.dataset = dataset
        self.tree = []
        self.lvl_count = -1
        self.leaf_level = self.leaf_lvl()
        self.merkleRoot = None
        self.merkle_root()

    def leaf_lvl(self): # generate first level of hashed transactions in pairs  (leaf nodes)
        print(self.dataset)
        if len(self.dataset) % 2 == 0: # check leaf length is even because merkle trees are a form of binary tree
            self.nxt_lvl()
            while len(self.dataset) > 0: # generate leaf nodes, append to leaf level until dataset is empty
                leaf_node = repr(TreeNode(self.dataset))
                self.tree[self.lvl_count].append(leaf_node)
        else: # duplicate last element in dataset and add to level to make length even
            duplicate = self.dataset[-1] 
            self.dataset.append(duplicate)
            self.leaf_lvl() 
        return self.tree[0]

    def nxt_lvl(self): # generate next level in tree
            self.nxt = []
            self.tree.append(self.nxt)
            self.lvl_count += 1
            return self.lvl_count # returns incremented lvl count for lvl count reassignment
        
    
    def merkle_root(self):
        transfer = []
        i_count = 0
        for i in self.tree[-1]: # generate parent nodes from child nodes of current level
            i_count += 1
            if i_count % 2 == 0:
                transfer.append([self.tree[-1][(self.tree[-1].index(i))-1], i])
            else:
                pass

        if len(self.tree[-1]) != 1: # if root node has not been reached
            self.nxt_lvl() # generate the next level in tree

        for pair in transfer: # fill next level with the generated parent nodes
            hash_input = (str(pair[0]) + str(pair[1])).encode("utf-8")
            parent_node = hashlib.sha256(hash_input).hexdigest() # generate parent node
            self.tree[self.lvl_count].append(parent_node)
        for pair in transfer:
            transfer.pop(transfer.index(pair)) # empty transfer

        if len(self.tree[-1]) > 1:
            self.merkle_root() # recursisely generate next level

        else: # merkle root has been reached
            print(self.tree)
            print(self.tree[self.lvl_count])
            root = (self.tree[self.lvl_count][0]) # index of root node
            self.merkleRoot = root
            return root
        
    def generate_proof(self, target_node):
        proof_path = []
        level = self.tree[-1]
        index = level.index(target_node) # index of the leaf node of choice
        
        if target_node not in level: # confirms target node is not in tree
            raise ValueError("Target node not found in the Merkle Tree.")

        while index > 0: # traverses Merkle tree along path a leaf node takes to reach the root node, picking up sibling nodes that are used
            sibling_index = index - 1 if index % 2 == 1 else index + 1 # index of a sibling node that is used for hash of parent node in path
            sibling_node = level[sibling_index]
            proof_path.append(sibling_node)
            index = (index - 1) // 2 

        return MerkleProof(proof_path, target_node)
    
class MerkleProof: # if the desired leaf node is in the tree, the merkle proof returns the path it takes to reach the root
    def __init__(self, path, target_node):
        self.path = path  # List of hashes along the path
        self.target_node = target_node  # The hash of the target node

    def __repr__(self):
        return f"MerkleProof(path={self.path}, target_node={self.target_node})"

class Block:
    '''basic structure of a block, block manipulation methods, block mining, block validation'''

    def __init__(self, transactions, blockchain):
        self.transactions = transactions
        self.block_height = len(blockchain.get_chain()) # index of latest block + 1 in chain
        if blockchain.get_chain() == []:
            self.previous_hash = 0 # genesis block creation
        else:
            self.previous_hash = blockchain.get_chain()[-1].get_block_hash() # block hash of newest block in chain
        self.timestamp = datetime.now().strftime("%H:%M:%S")
        self.merkle_root = self.calculate_merkle_root() # used to check if a specific transaction is in the block efficiently (merkle proof)
        self.nonce = 0 # incremented for mining
        self.difficulty_target = blockchain.get_difficulty_target()
        self.block_header = f'''block_height = {self.block_height}, 
                            previous_hash = {self.previous_hash}, 
                            timestamp = {self.timestamp}, 
                            merkle_root = {self.merkle_root},
                            transactions = {self.transactions},
                            difficulty_target = {self.difficulty_target}''' # ready format for hashing
        self.block_hash = None

    def calculate_merkle_root(self):
        '''calculate merkle root from transaction list'''
        ThisMerkleTree = MerkleTree(self.transactions)
        # generate merkle tree and return merkle root
        return ThisMerkleTree.merkle_root()

    def calculate_block_hash(self): 
        '''take block header and hash it, if hash meets difficculty target, return, if not, increment nonce and repeat'''
        hash_input = self.block_header + str(self.nonce)
        block_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
        while block_hash[0: (self.difficulty_target)] != "0"*self.difficulty_target: # keep mining while difficulty target is not met
            print(block_hash[0: (self.difficulty_target)])
            print(self.nonce)
            self.nonce += 1 # increment nonce and mine again
            hash_input = self.block_header + str(self.nonce)
            block_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
            print(block_hash)
        self.block_hash = block_hash

    def get_block_hash(self):
        return self.block_hash

    def is_block_valid(self):
        check = []
        # block header information and structure is correct
        hash_portion =  self.block_hash[0: self.difficulty_target] # check if hash meets difficulty target
        if str(hash_portion) == "0" * self.difficulty_target:
            check.append(True)
        else:
            check.append(False)
        def validate_transactions(): # validate each transaction (verifying digital signatures)
            for transaction in self.transactions:
                check.append(transaction.validate_transactions())
        validate_transactions()
        # transaction double spending prevented (no duplicate transactions)

        return all(check) # returns true if all elements are true

    def get_transactions(self):
        return self.transactions

    def get_block_header(self):
        return self.block_header

    def adjust_difficulty(self, difficulty):
        self.difficulty_target = difficulty

class Blockchain():
    # the data structure that all nodes base their copy of the blockchain off, and manipulating incoming / outgoing messages of the network

    def __init__(self):
        self.chain = []
        self.transaction_pool = []

    def genesis_block(self, issuance): # issuance is the first amount of currency the program starts with
        genesis_block = Block(issuance, self) # generates the first currency on the program and has no previous hash so it must be hardcoded in
        return genesis_block

    def get_chain(self):
        return self.chain

    def add_block(self, block):
        '''adds a new block to the chain'''
        self.chain.append(block)

    def get_latest_block(self):
        '''retrieves the latest block in the chain'''
        return self.chain[-1]

    def mine_block(self, block):
        # initiate mining process, solving hash puzzle (called by miner node)
        block.calculate_block_hash()
        return block

    def confirm_transaction(self, transaction): # constantly run by network for each transactions
        # confirm inclusion of a transaction in a block by incrementing confirmation count for each block that is added after block of said transaction (6=confirmed)
        for block in self.chain[::-1]:
            if transaction in block.get_transactions(): #  searches for block containing transaction USE MERKLE PROOF INSTEAD
                transaction_depth = len(self.chain) - self.chain.index(block) # length from end of chain to block containing transaction
                if transaction_depth >= 6:
                    return True
        return False # returns false if required transaction depth has not reached
    
    def get_difficulty_target(self):
        # listen to difficulty target from network
        return 4 # example for prototype

'''Block & Blockchain Testing''' 

# blockchain and genesis block creation
Blockchain1 = Blockchain()
genesis_dataset = ExampleDataset(8).set()
genesis_block = Blockchain1.genesis_block(genesis_dataset)
Blockchain1.add_block(genesis_block) # create the first block and add it to blockchain
print(Blockchain1.get_chain())

# block mining and creation
ExDataset1 = ExampleDataset(8).set()
block01 = Block(ExDataset1, Blockchain1) # create the block
block01.calculate_block_hash() # mine the block

# adding block to the blockchain
print(block01.is_block_valid()) # check validity
Blockchain1.add_block(block01) # add block
print(Blockchain1.get_chain()) # show chain

'''Testing Merkle Tree'''

ExDS = ExampleDataset(8).set() # create dataset with 8 randomly generated numbers between 0 and 9 inclusive
print(ExDS)

ExMerkleTree = MerkleTree(ExDS) # generate merkle tree from dataset
print(ExMerkleTree.merkleRoot) # print root of the merkle tree

'''Testing Merkle Tree (Odd length leaf layer of tree)'''
Ex2DS = ExampleDataset(9).set() # create dataset with 9 randomly generated numebrs
print(Ex2DS)

Ex2MerkleTree = MerkleTree(Ex2DS) # generate merkle tree from dataset
print(Ex2MerkleTree.tree)
print(Ex2MerkleTree.merkleRoot) # print root of the merkle tree


'''Merkle Proof Testing'''

# test the blockchains ways of preventing attacks 


'''Wallet Generation & Transaction Testing'''

'''User Creation'''
# Me = Wallet()
# Me.generate_keypair()
# # print(Me.public_key)
# # print(Me.private_key)

# You = Wallet()
# You.generate_keypair()

'''Transaction between Users'''

# NewTransaction = Me.create_transaction(You, 5) # sending transaction
# print(NewTransaction.validate_transaction()) # validating transaction
# print(repr(NewTransaction)) # string representation of transaction (digital signature is very large)

'''Full Program Cycle Test'''

# user is generated

# user makes transaction

# transaction is verified and added to transaction pool

# block is created with transaction

# block is verified and added to blockchain