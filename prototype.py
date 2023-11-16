import hashlib
from datetime import datetime
import math
import random

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
    
    def sign_transaction(self, private_key):
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


'''Testing User-end'''

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

class ExampleDataset: # for testing merkle tree functionality and behaviour of transaction objects 
    def __init__(self, length):
        self.dataset = []
        self.length = length # desired length of example dataset

    def data_gen(self): # generate single item of data (random integer in place of transactions)
            data = random.randint(0, 9)
            return data

    def set(self): # generate dataset 
        while len(self.dataset) < self.length:
            data = self.data_gen()
            self.dataset.append(data)
        return self.dataset
    
    def item_transfer(self): # transfer element out of dataset
        length = len(self.dataset)
        index = random.randint(0, length - 1)
        return self.dataset.pop(index)
class TreeNode: # node class to store all transactions individually in nodes, merkle tree is made up of these nodes through aggregation
    def __init__(self, dataset):
        self.dataset = dataset
        self.node = []
        self.fill()
        self.content = self.node[0]

    def fill(self): # take one element of data from dataset and form node (hashed)
        self.item = self.dataset.item_transfer() # pops (returns) random element out of dataset
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
        if len(self.dataset.dataset) % 2 == 0: # check leaf length is even because merkle trees are a form of binary tree
            self.nxt_lvl()
            while len(self.dataset.dataset) > 0: # generate leaf nodes, append to leaf level until dataset is empty
                leaf_node = repr(TreeNode(self.dataset))
                self.tree[self.lvl_count].append(leaf_node)
        else: # duplicate last element in dataset and add to level to make length even
            duplicate = self.dataset.dataset[-1] 
            self.dataset.dataset.append(duplicate)
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

        self.nxt_lvl() # generate the next level in tree

        for pair in transfer: # fill next level with the generated parent nodes
            hash_input = (str(pair[0]) + str(pair[1])).encode("utf-8")
            parent_node = hashlib.sha256(hash_input).hexdigest()
            self.tree[self.lvl_count].append(parent_node)
        for pair in transfer:
            transfer.pop(transfer.index(pair)) # empty transfer

        if len(self.tree[-1]) > 1:
            self.merkle_root() # recursisely generate next level

        else: # merkle root has been reached
            root = (self.tree[self.lvl_count][0])
            self.merkleRoot = root
            return root
        

'''Testing Merkle Tree'''

ExDS = ExampleDataset(8) # create dataset with 8 places for elements
ExDS.set() # generate random integers between 0 and 9 inclusive for dataset
print(ExDS.dataset)

ExMerkleTree = MerkleTree(ExDS) # generate merkle tree from dataset
print(ExMerkleTree.merkleRoot) # print root of the merkle tree

'''Testing Merkle Tree (Odd length leaf layer of tree)'''
Ex2DS = ExampleDataset(9) # create dataset with 8 places for elements
Ex2DS.set() # generate random integers between 0 and 9 inclusive for dataset
print(Ex2DS.dataset)

Ex2MerkleTree = MerkleTree(Ex2DS) # generate merkle tree from dataset
print(Ex2MerkleTree.tree)
print(Ex2MerkleTree.merkleRoot) # print root of the merkle tree

class Block:
    pass

class Blockchain:
    pass