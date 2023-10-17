import hashlib
import datetime
import random

class Blockchain:
    # chain
    # difficulty target

    # genesis block
    
    pass

class Block:
    # signature hash
    # previous hash
    # merkle root
    # nonce
    # timestamp
    # difficulty target
    # block height

    # generate hash

    # proof-of-work

    def __init__(self, chain):
        self.chain = chain
        self.signature_hash = None
        self.previous_hash = None
        self.merkle_root = None
        self.nonce = None
        self.timestamp = datetime.datetime.now()
        self.difficulty_target = None
        self.block_height = None

    def block_header(self):
        block_header = f'{self.previous_hash}{self.merkle_root}{self.timestamp}'
        return block_header
        pass

    def pow(self):
        while hash_input > self.difficulty_target:
            hash_input = (self.block_header() + str(self.nonce)).encode("utf-8")
            hash_int = hashlib.sha256(hash_input)
            if hash_int > self.difficulty_target:
                self.nonce += 1
        # somethin
        pass

    def hash_gen(self):
        pass
 

    pass