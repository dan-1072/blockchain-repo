import hashlib

class Transaction():

    def __init__(self, sender_address, recipient_address, amount, fee):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.amount = amount
        self.transaction_fee = fee
        self.timestamp = None
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