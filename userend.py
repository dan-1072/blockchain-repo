import hashlib
import datetime
import random
import math

class Transaction():

    def __init__(self, sender_address, recipient_address, amount, fee):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.amount = amount
        self.transaction_fee = fee
        self.timestamp = datetime.now().strftime("%H:%M:%S")
        self.transactionID = None
        self.digital_signature = None

    def Serialise(self):
        # serialise the transaction object into a suitable format for transmission over the network
        pass

    def Deserialise(self, data):
        # Deserialise data into transaction object
        pass

    def CalculateTransactionID(self):
        # Calculate hash of the transaction's contents to represent transaction when referenced on blockchain
        pass

    def ValidateTransaction(self):
        # check if the user has sufficient funds, verify the signature
        pass

class Wallet():

    def __init__(self):
        self.public_key = None 
        self.private_key = None
        self.address = None # derived from the public key, represents user on the blockchain
        self.balance = 0
        self.transaction_history = None
        self.blockchain_client = None # understand this

    def GenerateKeyPair(self):
        # generate the mathematically linked public and private key using RSA encryption
        pass

    def CreateTransaction(self):
        # create a transaction object specifying the recipient's address and amount sending
        pass

    def SignTransaction(self):
        # verify transaction, ownership of wallet, using asymmetric encryption
        pass

    def SendTransaction(self):
        # broadcast transaction to the network through blockchain client
        pass

    def UpdateBalance(self):
        # query blockchain and update wallet's balance off of transactions associated with wallet
        pass

    def TransactionHistoryManagement(self):
        # fetching and storing transaction records
        pass

    def SecureKeyStorage(self):
        # methods for securely storing the private key
        pass

class RSA:
    
    def is_primese(self, n):
        # check if a number is prime
        pass

    def generate_prime(self, bits):
        # generate prime number with given amount of bits
        pass

    def gcd(self, a, b):
        # calculate greatest common divisor of a and b
        pass

    def modinv(self, a, m):
        # calculte modular multiplicative inverse (extended Euclidean alorithm)
        pass

    def generate_keypair(self, bits):
        # generate the mathematically linked public key and private key with given amount of bits
        pass

    def encrypt(self, message, private_key):
        # encrypt a message with the private key using RSA
        pass

    def decrypt(self, ciphertext, public_key):
        # decrpy an RSA encrypted ciphertext with the public key, returning the original message
        pass