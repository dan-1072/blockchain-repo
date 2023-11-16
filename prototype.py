import hashlib
import datetime
import math
import random

class RSA:
    def __init__(self, key_length=1024):
        self.key_length = key_length

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
        while True:
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

    def create_transaction(self, recipient_pk, amount):
        transaction = Transaction(self.public_key, recipient_pk, amount, self.sign_transaction(transaction.transactionID))

    def sign_transaction(self, transactionID):
    # create digital signature on transaction
        '''encryption for signing transactions'''
        cipher_text = [pow(ord(char), self.private_key[0], self.private_key[1]) for char in transactionID] # pow function is exponentiation
        return cipher_text
    
    def ValidateTransaction(self, broadcaster, digital_signature, transactionID):
    # check if user has sufficient funds, verify signature
        broadcaster_pk = broadcaster.public_key
        plain_text = ''.join([chr(pow(char, broadcaster_pk[0], broadcaster_pk[1])) for char in digital_signature]) # pow function is exponentiation
        if plain_text == transactionID:
            return True
        else:
            return False

    # check balance

class Transaction():

    def __init__(self, sender_address, recipient_address, amount, digital_signature):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.amount = amount
        self.timestamp = datetime.now().strftime("%H:%M:%S")
        self.transactionID = self.CalculateTransactionID()
        self.digital_signature = digital_signature

    def CalculateTransactionID(self):
        # Calculate hash of the transaction's contents to represent transaction when referenced on blockchain
        transaction_data = f"{self.sender_address}{self.recipient_address}{self.amount}{self.timestamp}"
        transactionID = hashlib.sha256(transaction_data).hexdigest()
        return transactionID
        

class Block:
    pass

class Blockchain:
    pass