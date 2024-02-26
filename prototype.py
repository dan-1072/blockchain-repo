

'''this github repository and the following code is the work of Daniel Mirnejhad (candidate number 6416) for the AQA A-level Computer Science Non-Examination Assessment'''


import hashlib # hashiing function (sha-256)
from datetime import datetime # timestamps in blocks
import random # example dataset generation
import time # testing mining times
import socket # blockchain network
import threading # efficient handling of multiple connections between nodes at once
import pickle # for message serialisation and deserialisation
import enum # for differentiating between transactions and blocks over broadcasting in the network
import math # used for logarithms to calculate difficulty target
test = False # used for testing individual classes (not the final test)


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
    '''contains functions for implementing RSA encryption to generate a public-private key pair for wallets'''

    def __init__(self, key_length=1024):
        self.key_length = key_length # desired length of keys (longer keys are more computationally intensive to crack)

    def is_prime(self, n, k=5):
        """Miller-Rabin primality test, test if a number is prime (test is repeated as it is not perfectly accurate).
        name: is_prime
        parameters: n (number to test to see if it is a prime number), k (amount of times to repeat test for more accuracy)
        returns: Boolean (True if n is prime, False if n is not prime)
        """
        if n <= 1 or n % 2 == 0:
            return False
        if n == 2 or n == 3:
            return True
        
        r, d = 0, n - 1 # n = 2^r * d + 1 (to test for primality)
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k): # loop for trying different values of a, repeated iterations of test - for higher accuracy of generating a prime
            a = random.randint(2, n - 2)
            x = pow(a, d, n) # a to the power of d, modulo n
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1): # _ indicates variable looped through is not actually used in the loop, for readability 
                x = pow(x, 2, n) # x squared, modulo n
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_prime(self, bits):
        """Generate a random prime number with the specified number of bits.
        name: generate_prime
        parameters: bits (size of generated prime number)
        returns: num (prime number that is found using is_prime method)
        """
        while True: # generate random numbers until the number passes Miller-Rabin primality test
            num = random.getrandbits(bits)
            if self.is_prime(num):
                return num

    def egcd(self, a, b):
        """Extended Euclidean Algorithm to find the greatest common divisor between two numbers for finding modular inverses and finds the coefficients of the two numbers
        such that the linear combination of the two numbers result in the greatest common divisor between them.
        name: egcd
        parameters: a, b (two values for which we find the greatest common divisor of)
        returns: g, x, y (g is the greatest common divisor, x and y are the coefficients of the two numbers such that the linear combination of the two numbers result in the GCD
        """
        if a == 0:
            return (b, 0, 1)
        else:
            g, x, y = self.egcd(b % a, a)
            return (g, y - (b // a) * x, x)

    def modinv(self, a, m):
        """calculates the modular multiplicative inverse of an integer a modulo m, which is an integer x such that a multiplied by x, modulo m, is congruent to 1.
        name: modinv
        parameters: a, m (a is multiplied by some value x and then is taken modulo m such that it is congruent to 1)
        returns: x modulo m (the modular inverse of a modulo m)
        """
        g, x, y = self.egcd(a, m)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % m

    def generate_keys(self):
        ''' generates mathematically linked public-private key pair using RSA encryption - generating two large primes and using the fact that given a number that is the product 
        of two large primes it is computationally infeasible to derive the two primes from it and using the properties of modular exponentiation
        name: generate_keys
        parameters: None
        returns: public-private key pair (both including the product of primes and an exponent which undo eachothers effects when exponentiating the product of primes by both exponents modulo phi )
        '''
        p = self.generate_prime(self.key_length // 2) # Generate two large random prime numbers
        q = self.generate_prime(self.key_length // 2)
        n = p * q # Compute n (modulus)
        phi = (p - 1) * (q - 1) # Compute euler totient function value of p and q (phi)
        e = 65537  # Choose public exponent (65537 is a Commonly used value in RSA)
        d = self.modinv(e, phi) # Compute private exponent d
        public_key = (e, n)# Public key (e, n)
        private_key = (d, n) # Private key (d, n)
        return public_key, private_key 

    def encrypt(self, plaintext, d, n):
        '''encryption for signing transactions by exponentiating by private exponent which can be undone by public exponent to confirm the holder of the public key has the private key
        name: encrypt
        parameters: plaintext (some message to encrypt using RSA), d (the private exponent to encrypt message which can be undone (decryption) by public exponent), n (mod value of process)
        returns: cipher_text (the encrypted message)
        '''
        cipher_text = [pow(ord(char), d, n) for char in plaintext] # pow function is exponentiation
        return cipher_text

    def decrypt(self, cipher_text, e, n):
        '''decryption for verifying digital signatures by properties of modular exponentiation (undoing the effects of exponentiation from private exponent using exponentiation of public)
        name: decrypt
        parameters: cipher_text (some encrypted message to decrypt using RSA), e (the public exponent to decrypt ciphertext by exponentiation), n (mod value of process)
        returns: plain_text (decrypted ciphertext)
        '''
        plain_text = ''.join([chr(pow(char, e, n)) for char in cipher_text]) # pow function is exponentiation
        return plain_text

class Wallet:

    def __init__(self):
        self.public_key = None
        self._private_key = None
        self.transactions = []
        self._balance = 0

    def generate_keypair(self):
        '''generate public and private key pair used to represent the user and sign transactions respectively
        name: generate_keypair
        parameters: None
        returns: None
        '''
        self.public_key, self.private_key = RSA().generate_keys()

    def create_transaction(self, recipient_wallet, amount):
        ''' create a transaction object representing a transaction between self (sending from this wallet) and a different wallet
        name: create_transaction
        parameters: recipient_wallet (the wallet that will be on the receiving end of the transaction), amount (amount sent)
        returns: transaction (a transaction object representing this transaction between this wallet and the receiver given some amount)
        '''
        if amount < 0:
            print('invalid transaction')
            return
        recipient_pk = recipient_wallet.reveal_pk()
        transaction = Transaction(self.public_key, recipient_pk, amount, self.private_key, self, recipient_wallet) # automatically signs transaction
        return transaction
    
    def validate_transaction(self, broadcaster, digital_signature, transactionID):
        '''verify digital signature, authenticating the user
        name: validate_transaction
        parameters: broadcaster (wallet of the user that has created the transaction), digital_signature (digital_signature of the transaction made by the broadcaster encrypting
        with their private key) transactionID (transactionID of the transaction representing the transaction's contents and date which is used to compare against decrypted digital_signature for verification)
        returns: Boolean (True if transactionID matches decrypted digital_signature, False if not)
        '''
        broadcaster_pk = broadcaster.public_key
        plain_text = ''.join([chr(pow(char, broadcaster_pk[0], broadcaster_pk[1])) for char in digital_signature]) # pow function is exponentiation
        if plain_text == transactionID:
            return True
        else:
            return False
    
    def evaluate_balance(self):
        '''check record of transactions involving the wallet (which are stored on the wallet as a part of their transaction history) and evaluate a final balance
        name: evaluate_balance
        parameters: None
        returns: balance (current balance given transaction history which accounts for income and outcome)
        '''
        balance = 0
        for transaction in self.transactions:
            if transaction.recipient_pk == self.public_key: # the amount from ingoing transactions is added to balance
                balance += transaction.amount
            elif transaction.sender_pk == self.public_key: # the amount from outgoing transactions is deducted from balance
                balance -= transaction.amount
        if balance >= 0:
            self._balance = balance
        return balance
    
    def sufficient_bal(self, amount):
        '''check if the user has the sufficient funds to make transaction
        name: sufficient_bal
        parameters: amount (unconfirmed transaction's amount that is specified to be leaving the user's balance)
        returns: Boolean (True if user has enough to allow transaction to go through, False if it would cause negative balance)
        '''
        balance = 0
        print(self.public_key)
        for transaction in self.transactions:
            print(f'past transaction: {transaction.amount} on the account {transaction.sender_pk}')
            if transaction.recipient_pk == self.public_key: # the amount from ingoing transactions is added to balance
                balance += transaction.amount
            elif transaction.sender_pk == self.public_key: # the amount from outgoing transactions is deducted from balance
                balance -= transaction.amount
        print(f'current calculated balance: {balance} vs 0')
        if balance >= 0:
            return True
        elif balance < amount:
            return False
        
    def add_transaction(self, transaction_obj):
        ''' add transaction to wallet's history of transactions
        name: add_transaction
        parameters: transaction_obj (the transaction object that is going to be added to the history of transactions)
        returns: None
        '''
        self.transactions.append(transaction_obj)
        
    def identify_pk(self, pk):
        '''check if a given public key is the same as this wallet's public key
        name: identify_pk
        parameters: pk (public key to check against)
        returns: self (public key of this wallet if they are equal, else None)
        '''
        if self.public_key == pk:
            return self
        
    def get_bal(self):
        '''returns current balance of this wallet as it is a protected attribute and shouldn't be accessed directly
        name: get_bal
        parameters: None
        returns: self._balance (current balance of this wallet)
        '''
        return self._balance
        
    def reveal_pk(self):
        '''returns the public key of this wallet
        name: reveal_pk
        parameters: None
        returns: self.public_key (public key of this wallet)
        '''
        return self.public_key
    
    def update_wallet(self, deserialised_wallet):
        '''takes a deserialised wallet and updates the current wallet to match the deserialised wallet as when a wallet is transferred over the network it is serialised and deserialised
        for efficiency which leads to a copy of the wallet object being sent, so any updates on the transmitted wallet such as balance updates are not actually affecting the real wallet
        name: update_wallet
        parameters: deserialised_wallet (the wallet that had changes made to it after being broadcasted across the network)
        returns: None
        '''
        self.transactions = deserialised_wallet.transactions
        self._balance = deserialised_wallet._balance


class Transaction():

    def __init__(self, sender_pk, recipient_pk, amount, private_key, sender_wallet, recipient_wallet):
        self.sender_pk = sender_pk
        self.recipient_pk = recipient_pk
        self.amount = amount
        self.timestamp = datetime.now().strftime("%H:%M:%S")
        self.transactionID = self.calculate_transactionID()
        self.digital_signature = self.sign_transaction(private_key)
        self.sender_wallet = sender_wallet
        self.recipient_wallet = recipient_wallet

    def calculate_transactionID(self):
        '''Calculate hash of the transaction's contents to represent transaction when referenced on blockchain
        name: calculate_transactionID
        parameters: None
        returns: transactionID (calculated by hashing (sha-256 library function) the contents of the transaction such as the involved user's public keys, the amount and the time of creation)
        '''
        transaction_data = f"{self.sender_pk}{self.recipient_pk}{self.amount}{self.timestamp}"
        transactionID = hashlib.sha256(transaction_data.encode('utf-8')).hexdigest() # encoded -> hashed (binary) -> converted to hexadecimal
        return transactionID
    
    def sign_transaction(self, private_key): 
        '''encryption for signing transactions, same process as encryption in RSA class but for ease of use, it is in this class too, as some parameters are no longer needed
        name: sign_transaction
        parameters: private_key (used for the encryption process of exponentiation with the private exponent, modulo n, n is also in the private key)
        returns: digital_signature (the resulting ciphertext of the encryption process which can be decrypted using the public key mathematically linked to the used private key)
        '''
        digital_signature = [pow(ord(char), private_key[0], private_key[1]) for char in self.transactionID] # pow function is exponentiation
        return digital_signature
    
    def validate_transaction(self):
        '''decryption for verifying digital signatures, ssame process as decryption in RSA class but for ease of use, it is in this class too, as some parameters are no longer needed)
        name: validate_transaction
        parameters: None
        returns: Boolean (True if public key used to decrypt is mathematically linked to the private key used to encrypt to make the digital signature, else False)
        '''
        # decrypt the encrypted transaction ID and compare to transaction ID of the transaction to see if decryption worked (keys are linked)
        decryption = ''.join([chr(pow(char, self.sender_pk[0], self.sender_pk[1])) for char in self.digital_signature]) # pow function is exponentiation
        if decryption == self.transactionID:
            return True
        else:
            return False

    def check_funds(self, sender):
        '''check if the user has the sufficient funds to make transaction
        name: check_funds
        parameters: sender (wallet of the user making the transaction to call sufficient_bal method on the wallet to check transaction history to see if user has enough to make transaction)
        returns: check (the Boolean value returned from the sufficient_bal method that takes the argument self.amount - amount specified in transaction)
        '''
        check = sender.sufficient_bal(self.amount)
        return check
        

    def update_records(self):
        '''update the list of transactions made for both sender and recipient by finding them through their public keys
        name: update_records
        parameters: None
        returns: None
        '''
        sender_obj = Wallet.identify_pk(self.sender_pk) # find wallets of sender and recipient by checking 
        receiver_obj = Wallet.identify_pk(self.recipient_pk)
        
        sender_obj.add_transaction(self) # update records of sender and recipient
        receiver_obj.add_transaction(self)
        
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

if test == True:
    # user / wallet generation
    Me = Wallet()
    Me.generate_keypair()
    You = Wallet()
    You.generate_keypair()

    # transaction between users
    NewTransaction = Me.create_transaction(You, 5) # sending transaction
    print('Example Transaction between 2 Users:')
    print(NewTransaction) # string representation of transaction (digital signature is very large)

    # validating transaction
    print('Verifying Digital Signature:')
    print(NewTransaction.validate_transaction())
    print('Checking Balances for Sufficient Funds:')
    print(NewTransaction.check_funds(Me)) # will return False as user has balance of 0

        
class MerkleNode:
    '''represents one node made up of the hash of two concatenated child nodes'''
    def __init__(self, left_node, right_node, hash_value): # tree is made by merkle nodes linking to eachother through attributes
        self.left_node = left_node
        self.right_node = right_node
        self.hash = hash_value
    
    def get_hash(self):
        '''returns the hash representation of the concatenation of the left and right child nodes
        name: get_hash
        parameters: None
        returns: self.hash (hash of the concatenation of the left and right child node that make up this parent node)
        '''
        return self.hash
    
class MerkleTree:

    def __init__(self, dataset):
        self.dataset = dataset
        self.tree = self.build_tree()
        self.root = self.get_root()

    def calculate_hash(self, left, right): # may be used to make leaf nodes (left and right are from dataset) or other nodes (L and R are hashes)
        '''takes two elements, converts them to strings, concatenates them, and calculates the hash of this concatenation
        name: calculate_hash
        parameters: left, right (left and right child nodes that will be used as the hash inputs for the parent node)
        returns: hashed (hexadecimal hash for the parent node)
        '''
        hash_input = str(left) + str(right)
        hashed = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
        return hashed

    def build_tree(self):
        '''builds the merkle tree of merkle nodes, providing a merkle root representing the hash of all nodes
        name: build_tree
        parameters: None
        returns: tree (the merkle tree, where the leaf nodes consist of the data and the nodes above are all made from the hashes of the two child nodes beneath it)
        '''
        leaf_nodes = []
        if len(self.dataset) % 2 != 0: # add hashed dataset values into leaf level in string form
            self.dataset.append(self.dataset[-1])
        for data in self.dataset:
            hash_input = str(data) # convert to string
            hashed_data = hashlib.sha256(hash_input.encode()).hexdigest()
            leaf_nodes.append(hashed_data)

        tree = [leaf_nodes]  # generate parent nodes from child nodes in previous level
        while len(tree[-1]) > 1: # generate next level until the root is reached  (level of length 1)
            parent_nodes = []
            for node in tree[-1][0:len(tree[-1]):2]: # tree[-1] is the current level of the tree
                left_node = node
                if left_node != tree[-1][-1]: # if left node isnt the last node then there is a right node (for checking purposes)
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
        '''returns the merkle root which is the root node of the merkle tree
        name: get_root
        parameters: None
        returns: root (root node object of the tree, of class MerkleNode)
        '''
        root = self.tree[-1][0]
        return root
    
    def merkle_proof(self, target_node):
        '''generates the sibling nodes that are in the path the target node takes to the root, providing a path of nodes you would need to concatenate and hash some leaf node with
        to reach the root node, this is used to verify a transaction is actually in the tree without looking at the information of the other data
        name: merkle_proof
        parameters: target_node (the data that the proof path will be generated for, which will be converted into what it would be if it was a leaf node in the tree)
        returns: proof_path (the path of nodes this leaf node would concatenate and hash with to reach the root node if it were in the merkle tree in the first place)
        '''
        target_node = hashlib.sha256(str(target_node).encode('utf-8')).hexdigest() # get target node into its leaf level form
        proof_path = []
        root_reached = False 
        current_level = 0 # index of current level 
        while root_reached == False: # traverse tree from target node to root 
            for i in range(0, len(self.tree[current_level]), 2): # pick up sibling nodes during traversal and add to proof path
                left_node = self.tree[current_level][i]
                right_node = self.tree[current_level][i + 1] if i + 1 < len(self.tree[current_level]) else None
                if left_node == target_node: # check if target node is either of the nodes just defined in the pair
                    proof_path.append(right_node)
                    target_node = self.calculate_hash(left_node, right_node) # target node for next level (hash of child nodes)
                elif right_node != None:
                    if right_node == target_node:
                        proof_path.append(left_node)
                        target_node = self.calculate_hash(left_node, right_node) # target node for next level (hash of child nodes)
            if current_level + 1 < len(self.tree) and len(self.tree[current_level + 1]) == 1: # check if the next level is within bounds and has a single root node
                root_reached = True # don't search the next level (not needed for the proof path)
            else:
                current_level += 1 # search the next level
        return proof_path
    
    def verify_proof(self, target_node, proof):
        '''takes a proof path and reconstructs the root with it, comparing the roots to verify if the proof is valid, verifying the target node
        name: verify_proof
        parameters: target_node (the data to check if it is in the tree), proof (the proof path the node representing the data will need to follow to eventually make the root node if it is in the tree)
        returns: Boolean (True if target_node is in the merkle tree, False if it is not in the merkle tree)
        '''
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

if test == True:
    dataset1 = ExampleDataset(4).get_dataset() # generate example dataset
    tree1 = MerkleTree(dataset1) # generate merkle tree from example dataset
    print('Merkle Tree:')
    print(tree1.tree)
    proof = tree1.merkle_proof("Data3") # generate proof path given a target node
    print('Merkle Proof:')
    print(proof)
    print('Proof Verification:')
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
        self.difficulty_target = blockchain.get_difficulty_target() # before block creation, node calculates difficulty target
        self.block_header = f'''block_height = {self.block_height}, 
                            previous_hash = {self.previous_hash}, 
                            timestamp = {self.timestamp},
                            merkle_root = {self.merkle_root},
                            transactions = {self.transactions},
                            difficulty_target = {self.difficulty_target}''' # ready format for hashing
        self.block_hash = None

    def calculate_merkle_root(self):
        '''calculate merkle root from transaction list as the leaf nodes of the Merkle tree
        name: calculate_merkle_root
        parameters: None
        returns: this_merkle_tree.get_root() (the merkle root of the generated tree that represents the transactions of the block)
        '''
        this_merkle_tree = MerkleTree(self.transactions)
        return this_merkle_tree.get_root() # generate merkle tree and return merkle root

    def calculate_block_hash(self): 
        '''take block header and hash it, if hash meets difficulty target (some amount of leading 0s in the hash), return, if not, increment nonce and repeat - this is the hash puzzle that must be solved to make a block
        name: calculate_block_hash
        parameters: None
        returns: None
        '''
        hash_input = self.block_header + str(self.nonce)
        block_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
        while block_hash[0: (self.difficulty_target)] != "0"*self.difficulty_target: # keep mining while difficulty target is not met
            self.nonce += 1 # increment nonce and mine again
            hash_input = self.block_header + str(self.nonce)
            block_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
            # time.sleep(0.1)
        self.block_hash = block_hash
        print('block successfully mined')


    def is_block_valid(self):
        '''validate block by checking block hash meets difficulty target, and that each transaction is valid (verify each transaction in set)
        name: is_block_valid
        parameters: None
        returns: Boolean (True if hash meets difficulty target by starting with enough 0s and if all transactions in block are valid, False if either condition is not met)
        '''
        check = []
        hash_portion =  self.block_hash[0: self.difficulty_target] # check if hash meets difficulty target
        if str(hash_portion) == "0" * self.difficulty_target:
            check.append(True)
        else:
            check.append(False)
        def validate_transactions(): # validate each transaction (verifying digital signatures)
            pass
            for transaction in self.transactions:
                check.append(transaction.validate_transaction())
        validate_transactions() # transaction double spending prevented (no duplicate transactions)
        print(f'is block valid: {all(check)}') # all() returns true if all elements are true
        return all(check)
    
    def get_block_hash(self):
        '''return block's hash as to not have to directly access the attribute
        name: get_block_hash
        parameters: None
        returns: self.block_hash (hash of the block's contents)
        '''
        return self.block_hash
    
    def get_transactions(self):
        '''return block's set of transactions
        name: get_transactions
        parameters: None
        returns: self.transactions (block's set of transactions)
        '''
        return self.transactions

    def get_block_header(self):
        '''return block's header which contains most of the information that determines a block's hash, it is used as part of the hash input
        name: get_block_header
        parameters: None
        returns: self.block_header (the information that determines a block's hash'''
        return self.block_header

    def adjust_difficulty(self, difficulty):
        '''given a level of difficulty (amount of 0s the computed hash of the block needs to start with at least), set the difficulty target attribute
        name: adjust_difficulty
        parameters: difficulty (amount of 0s the computed hash of the block needs to start with at least)
        returns: None'''
        self.difficulty_target = difficulty
    
    def transaction_check(self, transaction): # check if transaction is in the block efficiently (merkle proof)
        '''check if a transaction is in a block using merkle proofs (verifying that dataset has not been tampered with too)
        name: transaction_check
        parameters: transaction (the transaction to check if included in a block after the block's creation)
        returns: None
        '''
        this_merkle_tree = MerkleTree(self.transactions)
        print(f'merkle tree: {this_merkle_tree.tree}')
        proof_path = this_merkle_tree.merkle_proof(transaction)
        print(f'proof path: {proof_path}')
        verify = this_merkle_tree.verify_proof(transaction, proof_path)
        print(f'is transaction in transactions: {verify}')

class Blockchain():
    '''the data structure that all nodes base their copy of the blockchain off, and manipulating incoming / outgoing messages of the network'''

    def __init__(self):
        self.chain = []
        self.transaction_pool = [] # unconfirmed, verified transactions
        self.difficulty_target = None # adjusted by network node directly on each block creation

    def add_transaction(self, transaction):
        '''adds a transaction to the transaction pool of unconfirmed transactions waiting to be used for a block
        name: add_transaction
        parameters: transaction (transaction to add to transaction pool)
        returns: None
        '''
        self.transaction_pool.append(transaction)

    def genesis_block(self, issuance, node_wallet): # issuance is the first amount of currency the program starts with (starting in the node's wallet)
        '''first block on blockchain is hardcoded in as it has no previous hash and the transaction represents issuance ("printing" currency)
        name: genesis_block
        parameters: issuance (amount to be hardcoded into the blockchain in the beginning, only other way to introduce currency is through block rewards)
                    node_wallet (wallet of the node that is initialising the network, as the issuance goes to them and they can act as a participant on the network as all nodes can)
        returns: genesis block (first block in the chain that introduces the issuance and has no actual previous hash unlike all other blocks so it is hardcoded into chain)
        '''
        node_wallet._balance = issuance # directly change balance of wallet of node to issuance to hardcode genesis block into chain
        genesis_transaction = node_wallet.create_transaction(node_wallet, issuance) # record issuance as the first transaction on the blockchain
        node_wallet.add_transaction(genesis_transaction)
        genesis_block = Block([genesis_transaction], self) 
        return genesis_block

    def get_chain(self):
        '''returns the chain (list of blocks) in the blockchain
        name: get_chain
        parameters: None
        returns: self.chain (the array of blocks in the blockchain)
        '''
        return self.chain

    def add_block(self, block):
        '''adds a new block to the chain
        name: add_block
        parameters: block (block to add to chain, usually is called after creating and validating a block)
        returns: None
        '''
        self.chain.append(block)

    def get_latest_block(self):
        '''retrieves the latest block in the chain
        name: get_latest_block
        parameters: None
        returns: self.chain[-1] (the last block added to the chain, used for the purpose of retrieving the hash value of the block that is coming before a new block)
        '''
        return self.chain[-1]

    def mine_block(self, block):
        '''initiate mining process, solving hash puzzle (called by miner node)
        name: mine_block
        parameters: block (unconfirmed block that holds the data of a block but has not been mined yet)
        returns: block (after being mined, meaning a nonce value such that the hash of the block meets the difficulty target is found and added to the block's block header)
        '''
        block.calculate_block_hash()
        self.transaction_pool = [] # empty transaction pool
        return block

    def confirm_transaction(self, transaction):
        '''given some transaction, will return whether the transaction is considered as 'confirmed' (is 6 blocks deep in the chain) as defence against malicious attacks
        name: confirm_transaction 
        parameters: transaction (transaction to search through blocks, from latest block, backwards through the chain)
        returns: Boolean (True if transaction is in a block that is 6 blocks or more deeper in the chain, False if block is in 5 newest blocks added)
        '''
        for block in self.chain[::-1]:
            if transaction in block.get_transactions(): #  searches for block containing transaction 
                transaction_depth = len(self.chain) - self.chain.index(block) # length from end of chain to block containing transaction
                if transaction_depth >= 6:
                    return True
        return False # returns false if required transaction depth has not reached
    
    def get_difficulty_target(self):
        '''returns current difficulty target of this copy of the blockchain
        name: get_difficulty_target
        parameters: None
        returns: self.difficulty_target (current difficulty target of this copy of the blockchain)
        '''
        return self.difficulty_target
    
'''Block & Blockchain Testing''' 

if test == True:
    # blockchain and genesis block creation
    Blockchain1 = Blockchain()
    genesis_dataset = ExampleDataset(8).get_dataset()
    genesis_block = Blockchain1.genesis_block(genesis_dataset)
    Blockchain1.add_block(genesis_block) # create the first block and add it to blockchain
    print('Chain of Blockchain:')
    print(Blockchain1.get_chain())

    # block mining and creation
    ExDataset1 = ExampleDataset(8).get_dataset()
    block01 = Block(ExDataset1, Blockchain1) # create the block
    print('New Block Created')
    print('Mining Iterations:')
    block01.calculate_block_hash() # mine the block
    print('Difficulty Target (1) Met')

    # adding block to the blockchain
    block01.is_block_valid() # check validity
    Blockchain1.add_block(block01) # add block
    print('Show New Chain:')
    print(Blockchain1.get_chain()) # show chain

class MessageType(enum.Enum):
    '''defines incoming message types over the network, transaction or block, needed to handle serialisation differently'''
    TRANSACTION = 1
    BLOCK = 2

class Node:
    def __init__(self, host, port, client=None):
        self.host = host
        self.port = port
        self.peer_ports = []  # List of connected peers (ports on localhost)
        self.server = None
        self.miner_node = 0 # 0: is not a miner node, 1: is a miner node, used to check number of active miner nodes on network
        self.blockchain = Blockchain() # local copy of the network's blockchain
        self.wallet = Wallet() # nodes can act as participants on the network, making and receiving transactions
        self.listening = 1
        self.client = client

    def initialise_blockchain(self, issuance):
        '''hardcode genesis block into chain and generate the issuance (starting currency in circulation of the blockchain) using the genesis_block method of the blockchain class
        name: initialise_blockchain
        parameters: issuance (amount of starting currency the node's wallet will initialise the blockchain network with)
        returns: None
        '''
        self.wallet.generate_keypair() # generate public and private key for wallet of node
        genesis_block = self.blockchain.genesis_block(issuance, self.wallet) # create genesis block
        self.blockchain.add_block(genesis_block) # add genesis block to blockchain

    def start(self):
        '''initialises a server that listens for incoming messages: transactions from users and peer nodes, blocks from peer nodes
        name: start
        parameters: None
        returns: None
        '''
        try:
            if self.listening == 1: 
                self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # socket used to listen for incoming messages from peer nodes
                self.server.bind((self.host, self.port))
                self.server.listen(1)

            print(f"Node listening on {self.host}:{self.port}")

            while self.listening == 1: # always running until connection is broken
                client, address = self.server.accept() # block until a connection is established returning a new socket with the peer node
                print(f"Connection from {address}")

                peer_thread = threading.Thread(target=self.handle_peer, args=(client,)) # threads allow for efficient handling of multiple connections
                peer_thread.start() # thread calls handle peer to manage incoming messages on establish connections
        except socket.error:
            pass

    def handle_peer(self, client):
        '''manages communication with a connected peer node
        name: handle_peer
        parameters: client (the client that the node will be receiving data from)
        returns: None
        '''
        while True: 
            try:
                data = client.recv(65536)
                if not data:
                    break
                message = pickle.loads(data) # deserialisation
                self.handle_message(message)
            except Exception as e:
                print(f"Error handling peer: {e}")
                break

    def handle_message(self, message):
        '''directs received messages to transaction handling or block handling
        name: handle_message
        parameters: message (the received message from client)
        returns: None
        '''
        print(f'message being processed')
        if message['type'] == MessageType.TRANSACTION:
            self.handle_transaction(message['data'])
        elif message['type'] == MessageType.BLOCK:
            self.handle_block(message['data'])

    def handle_transaction(self, transaction):
        '''processes (validates) and adds transaction to the node's copy of the transaction pool, initiates the creation of a block if the transaction pool is full after addition
        name: handle_transaction
        parameters: transaction (the transaction received from client that is to be validated and, if valid, added to transaction pool to be added to a block)
        returns: None
        '''
        print(f"miner node received transaction")
        validation = transaction.validate_transaction() # transaction is validated
        if validation == True: # check if transaction is valid
            
            self.blockchain.add_transaction(transaction) # transaction is added to list of unconfirmed transactions on local copy of blockchain
            transaction.sender_wallet.transactions.append(transaction) # add transaction to sender's history of transactions
            transaction.recipient_wallet.transactions.append(transaction) # add transaction to recipient's history of transactions
            # self.broadcast_transaction(transaction) # broadcast the valid transaction to peer nodes for them to validate and add to their copies

            if len(self.blockchain.transaction_pool) == 4: # if transaction pool limit reached, empty transaction pool 
                print(f'blockchain')
                if self.miner_node == 1: # if node is a miner node, create a block with transactions and empty transaction pool
                    self.create_block(self.blockchain.transaction_pool) 
                    self.blockchain.transaction_pool = []
                elif self.miner_node == 0: # if node is not a miner node, just empty transaction pool
                    self.blockchain.transaction_pool = []

        elif validation == False:
            print('invalid transaction')
        print('blockchain updated')

    def handle_block(self, block):
        ''' processes (validates) and adds block to the node's copy of the blockchain
        name: handle_block
        parameters: block (the block to be validated and if valid, added to the node's copy of the blockchain, block is typically broadcasted from a differnt node)
        returns: None
        '''
        validation = block.is_block_valid() # validate the block
        if validation == True:
            self.blockchain.add_block(block) # add block if its valid
        elif validation == False:
            pass
        print(f"Received block: {self.miner_node} ") #{block}

    def adjust_difficulty(self):
        '''difficulty target algorithm to adjust the difficulty target each time a block is ready to start being mined again
        name: adjust_difficulty
        parameters: None
        returns: None
        '''
        active_miners = 1
        for node in self.peer_ports: # check list of nodes to see how many active miners there are
            if node.miner_node == 1:
                active_miners += 1
            elif node.miner_node == 0:
                pass
        t = 0.1 # time delay between block mining iterations of incrementing nonce value
        d = 60 # desired average time for network to produce a block (solve block puzzle)
        attempts = d / t
        difficulty_target = math.log(attempts*active_miners, 16) # equation for difficulty target given active miners and time delay such that mining takes 1 minute 
        self.blockchain.difficulty_target = math.ceil(difficulty_target) # round difficulty target up (decimal target not possible)

class MinerNode(Node):
    '''instances of this class can use the methods a typical node can use but they can also broadcast blocks to the network'''

    def __init__(self, host, port):
        super().__init__(host, port)

    def initialise_miner(self):
        '''confirm a node is a miner node in the attributes of the node object, miner nodes will be able to mine a block when the transaction pool is full
        name: initialise_miner
        parameters: None
        returns: None
        '''
        self.miner_node = 1

    def create_block(self, transactions):
        '''validate transactions and make sure that transactions do not lead to negative balances (taking into account users being involved in multiple transactions in one set of transactions) and make a block with the valid transactions
        name: create_block
        parameters: transactions (list of transactions to validate and use for a block)
        returns: None
        '''
        validated_transactions = []
        seen_wallets = []
        previous_wallet = None # for undoing 
        for transaction in transactions:
            for i in seen_wallets: # add transaction from transaction's wallets to updated wallet
                    if transaction.sender_wallet.public_key == i.public_key: # update wallet to last iteration's version
                        previous_wallet = i # keep track of previous wallet incase transaction ends up being invalid and wallet needs to get reverted
                        i.transactions.append(transaction)
                        previous_wallet_pos = seen_wallets.index(previous_wallet)
                        transaction.sender_wallet = i
                    elif transaction.recipient_wallet.public_key == i.public_key:
                        previous_wallet = i
                        i.transactions.append(transaction)
                        transaction.recipient_wallet = i
                        previous_wallet_pos = seen_wallets.index(previous_wallet)
            check = [] # validate transactions (no causes in negative balance) after adding new transactions to users' wallets 
            check.append(transaction.check_funds(transaction.sender_wallet))
            check.append(transaction.validate_transaction())
            if all(check) == False: # revert wallets back to initial state before transactions were added to evaluate balances, because the transaction is not going through
                if previous_wallet != None:
                    previous_wallet.transactions.pop()
                    seen_wallets[previous_wallet_pos] = previous_wallet # revert last wallet mutated to original state
                else:
                    pass
            elif all(check) == True: # transaction is going through
                validated_transactions.append(transaction)
                print('transaction validated')
                transaction.sender_wallet.evaluate_balance()
                transaction.recipient_wallet.evaluate_balance()
                if self.client != None: # counter different instances in memory from serialisation problem (synchronise wallet instances)
                    for wallet in self.client.users: # actual wallets are all updated to have the same state as these deserialised wallets that had the transaction added
                            if wallet.public_key == transaction.sender_wallet.public_key:
                                print(f'updating wallet')
                                seen_flag = 0
                                for j in seen_wallets:
                                    if wallet.public_key == j.public_key:
                                        seen_flag = 1
                                        pos = seen_wallets.index(j)
                                        wallet.update_wallet(transaction.sender_wallet)
                                if seen_flag == 0:
                                    seen_wallets.append(transaction.sender_wallet)
                                else:
                                    seen_wallets[pos] = transaction.sender_wallet
                            elif wallet.public_key == transaction.recipient_wallet.public_key:
                                print(f'updating wallet')
                                seen_flag = 0
                                for j in seen_wallets:
                                    if wallet.public_key == j.public_key:
                                        seen_flag = 1
                                        pos = seen_wallets.index(j)
                                        wallet.update_wallet(transaction.recipient_wallet)
                                if seen_flag == 0:
                                    seen_wallets.append(transaction.recipient_wallet)
                                else:
                                    seen_wallets[pos] = transaction.recipient_wallet
            else:
                print(f'invalid transaction')
        for k in self.client.users:
            for l in seen_wallets:
                if k.public_key == l.public_key:
                    k.update_wallet(l)
        if len(validated_transactions) != 0:
            self.adjust_difficulty() # recalculates difficulty target before block creation
            block = Block(validated_transactions, self.blockchain) # block is created
            block.calculate_block_hash() # block is mined 
            block.is_block_valid() # block is validated
            self.blockchain.add_block(block) # block is added to chain

        block_reward = 5 # reward for mining block, added into transaction pool
class BlockchainClient:
    '''Users who do not run nodes interact (making transactions, broadcasting it to the nodes) with the blockchain through a blockchain client'''
    def __init__(self, host, port, node):
        self.host = host
        self.port = port
        self.node = node
        self.users = []

    def send_transaction(self, transaction):
        '''send a transaction to the blockchain network'''
        if transaction.sender_wallet not in self.users:
            self.users.append(transaction.sender_wallet)
            print('user added')
        if transaction.recipient_wallet not in self.users:
            self.users.append(transaction.recipient_wallet)
            print('user added')
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket: # connect client to peer nodes on network
                client_socket.connect((self.host, self.port))

                message = {'type': MessageType.TRANSACTION, 'data': transaction} # serialise transaction
                serialised_message = pickle.dumps(message)

                client_socket.send(serialised_message) # send transaction to network

                print(f"Transaction sent from client")
        except Exception as e:
            print(f"Error sending transaction: {e}")

'''Full Program Testing'''

def start_node_in_thread(node):
    node.start()

user_1 = Wallet()
user_1.generate_keypair()
user_2 = Wallet()
user_2.generate_keypair()
user_3 = Wallet()
user_3.generate_keypair()
print(f'user profiles created')

regular_node = MinerNode('localhost', 5000)
blockchain_client = BlockchainClient('localhost', 5000, regular_node) # users broadcast transactions to network through client
regular_node.client = blockchain_client

regular_node.initialise_blockchain(100) # create genesis blocks and introduce issuance into chain circulation
regular_node.initialise_miner()

node_thread = threading.Thread(target=start_node_in_thread, args=(regular_node,))
node_thread.start() # connect to network and listen for incoming messages

t1 = regular_node.wallet.create_transaction(user_1, 11)
t2 = regular_node.wallet.create_transaction(user_2, 14)
t3 = regular_node.wallet.create_transaction(user_1, 6)
t4 = regular_node.wallet.create_transaction(user_3, 43)
t5 = user_2.create_transaction(user_3, 10)
t6 = user_3.create_transaction(regular_node.wallet, 1)
t7 = user_1.create_transaction(regular_node.wallet, 4)
t8 = regular_node.wallet.create_transaction(user_1, 300)
token = [t4, t2, t1, t3, t8, t6, t7, t5]
for ti in token:
    blockchain_client.send_transaction(ti)
    time.sleep(2)
print(regular_node.wallet.get_bal()) # 31
print(user_1.get_bal()) # 13
print(user_2.get_bal()) # 4
print(user_3.get_bal()) #  52

for bloc in regular_node.blockchain.get_chain()[1:]:
    print(f'amount of transactions in this block: {len(bloc.transactions)}')
    bloc.transaction_check(t8)


# prevent users from sending money to themself

# 1: users, client and nodes are generated
# 2: users or nodes make transactions
# 3: blockchain client sends transaction to node
# 4: node validates transaction and broadcasts to other nodes for other nodes to validate
# 5: transaction pool reaches limit
# 6: transaction pool is emptied and used as transactions for a block
# 7: merkle tree is generated
# 8: block is mined by node, block reward is given to miner in next block, added to local copy of chain and broadcasted to all other nodes on network to validate and add
# 9: transactions are successfully completed and cycle can restart


# transaction pool is filled
# miner nodes create blocks
# miner nodes compete to mine block
# winning miner broadcasts block to peer nodes
# block reward


'''Edge Case Scenario Testing (malicious attacks)'''

# invalidated digital signature
# transaction insufficient funds
# invalidated block (difficulty target not met)
# invalidated merkle root (transaction tampering)
# fork in the network, fork resolution
# nodes being added after blockchain is initialised

# to do: load users with history from database using a save