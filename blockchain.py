import datetime
import hashlib
import random

class Block:
    def __init__(self):
        self.block_height = None # index of latest block + 1 in chain
        self.previous_hash = None # block hash of newest block in chain
        self.timestamp = None 
        self.merkle_root = None
        self.nonce = 0
        self.transactions = None
        self.difficulty_target = None
        self.block_hash = None

    def CalculateBlockHash(self): 
        # takes block attributes and calculates the cryptographic hash representing this block
        pass

    def AddTransaction(self, transaction):
        pass

    def GetBlockHash(self):
        pass

    def IsBlockValid(self):
        pass

    def Serialise(self):
        pass

    def Deserialise(self):
        pass

    def GetTransactionCount(self):
        pass

    def GetTransactions(self):
        pass

    def GetBlockHeader(self):
        pass

    def AdjustDifficulty(self, difficulty):
        pass

class Blockchain():
    # the data structure that all nodes base their copy of the blockchain off, and manipulating incoming / outgoing messages of the network

    def __init__(self):
        self.chain = []
        self.transaction_pool = []
        self.genesis_block = None

    def AddBlock(self, block):
        # adds a new block to the chain
        pass

    def GetLatestBlock(self):
        # retrieves the latest block in the chain
        pass

    def IsChainValid(self):
        # checks validity of chain (compared lengths of local chain to received chain from network, longer chain is more valid)
        pass

    def ReplaceChain(self, chain):
        # replaces local chain with received chain from network)
        pass

    def BroadcastTransaction(self, transaction):
        # broadcast a received transaction to the network for peer nodes to receive and validate
        pass

    def HandleNewBlock(self, block):
        # validate and incorporate into the chain a received block from network
        pass

    def HandleNewTransaction(self, transaction):
        # validate a transaction from the network and add to mempool
        pass

    def MineBlock(self, transactions):
        # initiate mining process by creating a block with set of transactions, and solving hash puzzle (called by miner node)
        pass

    def ConfirmTransaction(self, transaction):
        # confirm inclusion of a transaction in a block by incrementing confirmation count for each block that is added after block of said transaction (6=confirmed)
        pass

class Cryptography():

    def sha_256(self):
        pass

    def rsa_encryption(self):
        pass