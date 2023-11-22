import hashlib
from datetime import datetime
import math
import random
import time
import sys
sys.setrecursionlimit(10**6) # mining is done recursively and may have many thousand iterations


class ExampleDataset: 
    '''generate example datasets in place of transactions for testing'''
    def __init__(self, length):
        self.dataset = []
        self.length = length # desired length of example dataset
        self.data_gen()

    def get_dataset(self):
        return self.dataset

    def data_gen(self): # generate data (unique strings in place of transactions)
        for i in range((self.length + 1)):
            string = f'Data{i}'
            self.dataset.append(string)

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
    

'''Wallet Generation & Transactions Testing'''

# user / wallet generation
Me = Wallet()
Me.generate_keypair()
You = Wallet()
You.generate_keypair()

# transactions between users
NewTransaction = Me.create_transaction(You, 5) # sending transaction
print(NewTransaction.validate_transaction()) # validating transaction
print(repr(NewTransaction)) # string representation of transaction (digital signature is very large)
        
class MerkleNode:
    '''represents one node made up of the hash of two concatenated child nodes'''
    def __init__(self, left_node, right_node, hash_value): # tree is made by merkle nodes linking to eachother through attributes
        self.left_node = left_node
        self.right_node = right_node
        self.hash = hash_value
    
    def get_hash(self):
        return self.hash
    
class MerkleTree:

    def __init__(self, dataset):
        self.dataset = dataset
        self.tree = self.build_tree()
        self.root = self.get_root()

    def calculate_hash(self, left, right): # may be used to make leaf nodes (left and right are from dataset) or other nodes (L and R are hashes)
        '''takes two elements, converts them to strings, concatenates them, and calculates the hash of this concatenation'''
        hash_input = str(left) + str(right)
        hashed = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
        return hashed

    def build_tree(self):
        '''builds the merkle tree of merkle nodes, providing a merkle root representing the hash of all nodes'''
        leaf_nodes = []
        # add hashed dataset values into leaf level in string form
        for data in self.dataset:
            hash_input = str(data) # convert to string
            hashed_data = hashlib.sha256(hash_input.encode()).hexdigest()
            leaf_nodes.append(hashed_data)

        tree = [leaf_nodes]
        # generate parent nodes from child nodes in previous level
        while len(tree[-1]) > 1: # generate next level until the root is reached  (level of length 1)
            parent_nodes = []
            for node in tree[-1][0:len(tree[-1]):2]: # tree[-1] is the current level of the tree
                left_node = node
                if left_node != tree[-1][-1]: # if left node isnt the last node then there is a right node
                    right_index = tree[-1].index(node) + 1
                    right_node = tree[-1][right_index]
                else:
                    right_node = None
                parent_hash = self.calculate_hash(left_node, right_node)
                parent = MerkleNode(left_node, right_node, parent_hash)
                parent_nodes.append(parent.get_hash())
            tree.append(parent_nodes)
        return(tree)
    
    def get_root(self):
        root = self.tree[-1][0]
        return root
    
    def merkle_proof(self, target_node):
        '''generates the sibling nodes that are in the path the target node takes to the root'''
        target_node = hashlib.sha256(str(target_node).encode('utf-8')).hexdigest() # get target node into its leaf level form
        proof_path = []
        root_reached = False 
        current_level = 0 # index of current level 
        while root_reached == False: # traverse tree from target node to root 
            # pick up sibling nodes during traversal and add to proof path
            for node in self.tree[current_level][0:len(self.tree[current_level]):2]: # look at every other node (first node of a pair) 
                left_node = node
                if self.tree[current_level][-1] != node: # if left node isnt last node in tree
                    right_index = self.tree[current_level].index(left_node) + 1 # one index after left node in the current level
                    right_node = self.tree[current_level][right_index] 
                # check if target node is either of the nodes just defined in the pair
                if left_node == target_node: 
                    proof_path.append(right_node)
                    target_node = self.calculate_hash(left_node, right_node) # target node for next level (hash of child nodes)
                elif right_node == target_node:
                    proof_path.append(left_node)
                    target_node = self.calculate_hash(left_node, right_node) # target node for next level (hash of child nodes)
            if len(self.tree[current_level + 1]) == 1: # if the next level is the root 
                root_reached = True # dont search next level (not needed for proof path)
            else:
                current_level += 1 # search next level
        return proof_path
    
    def verify_proof(self, target_node, proof):
        '''takes a proof path and reconstructs the root with it, comparing the roots to verify if the proof is valid, verifying the target node'''
        target_node = hashlib.sha256(str(target_node).encode('utf-8')).hexdigest() # get target node into its leaf level form
        for node in proof: # contatenate and hash target node with proof node, concatenate and hash the previous hash with next proof node, so on
            current_level = proof.index(node) # works because there is only one sibling node per level in the proof path
            if self.tree[current_level].index(node) % 2 == 0: # all left childs of pairs have even node index in level 
                target_node = self.calculate_hash(node, target_node) # node is left child
            elif self.tree[current_level].index(node) % 2 == 1: # all right childs of pairs have odd node index in level
                target_node = self.calculate_hash(target_node, node) # node is right child
        if target_node == self.root: # check if root generated from proof is equal to actual root
            return True
        else:
            return False
        

'''Merkle Tree Testing'''

dataset1 = ExampleDataset(16).get_dataset() # generate example dataset
tree1 = MerkleTree(dataset1) # generate merkle tree from example dataset
print(tree1.tree)
proof = tree1.merkle_proof("Data3") # generate proof path given a target node
print(proof)
print(tree1.verify_proof("Data3", proof)) # verify that target node is in merkle tree through proof path



class Block:
    '''basic structure of a block, block manipulation methods, block mining, block validation'''

    def __init__(self, transactions, blockchain):
        self.transactions = transactions
        self.block_height = len(blockchain.get_chain()) # index of latest block + 1 in chain
        if blockchain.get_chain() == []: # if blockchain is empty, create genesis block
            self.previous_hash = 0 # genesis block creation
        else:
            self.previous_hash = blockchain.get_chain()[-1].get_block_hash() # block hash of last block in chain
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
        this_merkle_tree = MerkleTree(self.transactions)
        # generate merkle tree and return merkle root
        return this_merkle_tree.get_root()

    def calculate_block_hash(self): 
        '''take block header and hash it, if hash meets difficculty target, return, if not, increment nonce and repeat'''
        hash_input = self.block_header + str(self.nonce)
        block_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
        while block_hash[0: (self.difficulty_target)] != "0"*self.difficulty_target: # keep mining while difficulty target is not met
            print(self.nonce)
            self.nonce += 1 # increment nonce and mine again
            hash_input = self.block_header + str(self.nonce)
            block_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
            print(block_hash)
        self.block_hash = block_hash


    def is_block_valid(self):
        '''validate block by checking block hash meets difficulty target, and that each transaction is valid (verify each transaction in set)'''
        check = []
        # block header information and structure is correct
        hash_portion =  self.block_hash[0: self.difficulty_target] # check if hash meets difficulty target
        if str(hash_portion) == "0" * self.difficulty_target:
            check.append(True)
        else:
            check.append(False)
        def validate_transactions(): # validate each transaction (verifying digital signatures)
            pass
        #     for transaction in self.transactions:
        #         check.append(transaction.validate_transaction())
        # validate_transactions()
        # transaction double spending prevented (no duplicate transactions)

        print(f'is block valid: {all(check)}') # all() returns true if all elements are true
    
    def get_block_hash(self):
        return self.block_hash
    
    def get_transactions(self):
        return self.transactions

    def get_block_header(self):
        return self.block_header

    def adjust_difficulty(self, difficulty):
        self.difficulty_target = difficulty
    
    def transaction_check(self, transaction): # check if transaction is in the block efficiently (merkle proof)
        '''check if a transaction is in a block using merkle proofs (verifying dataset has not been tampered with too)'''
        this_merkle_tree = MerkleTree(self.transactions)
        proof_path = this_merkle_tree.merkle_proof(transaction)
        verify = this_merkle_tree.verify_proof(proof_path, transaction)
        print(f'is transaction in transactions: {verify}')

class Blockchain():
    '''the data structure that all nodes base their copy of the blockchain off, and manipulating incoming / outgoing messages of the network'''

    def __init__(self):
        self.chain = []
        self.transaction_pool = [] # unconfirmed, verified transactions

    def add_transaction(self, transaction):
        self.transaction_pool.append(transaction)


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
        self.transaction_pool = [] # empty transaction pool
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
        return 1 # example for prototype
    
'''Block & Blockchain Testing''' 

# blockchain and genesis block creation
Blockchain1 = Blockchain()
genesis_dataset = ExampleDataset(8).get_dataset()
genesis_block = Blockchain1.genesis_block(genesis_dataset)
Blockchain1.add_block(genesis_block) # create the first block and add it to blockchain
print(Blockchain1.get_chain())

# block mining and creation
ExDataset1 = ExampleDataset(8).get_dataset()
block01 = Block(ExDataset1, Blockchain1) # create the block
block01.calculate_block_hash() # mine the block

# adding block to the blockchain
print(block01.is_block_valid()) # check validity
Blockchain1.add_block(block01) # add block
print(Blockchain1.get_chain()) # show chain



'''Full Program Cycle Test'''

# user is generated

# user makes transaction

# transaction is verified and added to transaction pool (defence)

# block is created with transaction (defence)

# block is verified and added to blockchain (defence)