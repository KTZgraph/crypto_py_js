#coding=utf-8
"""
[!] Use Cryptodome instead of Crypto [!]
Crypto library have vulnerabilities
"""

from Cryptodome.Signature import PKCS1_v1_5 
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random


BLOCK_SIZE = 16

class Crypto:
    """
    """
    def __init__(self):
        pass
    
    @staticmethod
    def encrypt_AES(plain_text, key, iv=None, block_size=BLOCK_SIZE):
        """
        Encrypt plain_text with key and iv

        Args:
            key (bytes): AES key with length of block_size
            plain_text (bytes): data to encrypt, padded with pkcs7 style
            iv (bytes, optional): data to encrypt. 
                Default generated from AES key

        Returns:
            cipher_text (bytes): encrypted data

        Raises:
            ValueError: When encrypted data, and decrypted data are the same
            BaseException: When data can't be encrypted

        Note:
            [!] Never use ECB mode [!]

        """
        if not iv:
            iv = Crypto.get_iv(key)

        try:
            encryption_suite = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = encryption_suite.encrypt(pad(plain_text, BLOCK_SIZE, style='pkcs7'))

            if plain_text == cipher_text:
                raise PITException('Encryption failed - encrypted file is the same as original')

            return cipher_text
        except BaseException as exception:
            raise PITException("[AES] Encryption - can't encrypt data")

    @staticmethod
    def decrypt_AES(cipher_text, key, iv=None, block_size=BLOCK_SIZE):
        """
        Decryption AES

        Args:
            key (bytes): AES key, used to encrypt data
            iv (bytes): AES initialization vector
            cipher_text (bytes): encrypted data
            block_size (int): default 

        Returns:
            plain_text (bytes): decrypted cipher_text

        Notes:
            [!] Never use ECB mode [!]

        """
        if not iv:
            iv = Crypto.get_iv(key)
        decryption_suite = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(decryption_suite.decrypt(data_to_decrypt), block_size)
        return decrypted_data

    @staticmethod
    def encrypt_RSA(plain_text, public_key):
        """
        Encrypt data with RSA private key

        Args:
            plain_text (bytes): data to encrypt
            public_key (bytes): RSA public key, for encryption data

        Returns:
            cipher_text (bytes): encrypted data
        
        Raises:
            BaseException: When amount of data to encrypt are to big
        
        Notes:
            [!] Data to encrypt can't be to long [!]

        """
        pass
    
    @staticmethod
    def decrypt_RSA(cipher_text, rsa_private_key):
        """
        Decrypt data with RSA private_key

        Args:
            cipher_text (bytes): encrypted data
            rsa_private_key (str): private key RSA

        Returns:
            plain_text (bytes): decrypted cipher_text
        
        Raises:
            BaseException: when decryption is not possible
        
        Note:
            RSA cipher could only encrypt small amount of data

        """
        key = RSA.importKey(rsa_private_key)
        encryption_suite = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        plain_text = encryption_suite.decrypt(cipher_text)
        return plain_text

    @staticmethod
    def get_random_key(block_size=BLOCK_SIZE):
        """
        Generate random block_size-length for encryption with AES cipher

        Args:
            block_size(int, optional): Default 16

        Returns:
            random_bytes (bytes): block_size-length random bytes. Default 16 length

        """
        random_bytes = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(block_size))
        return bytes(random_bytes.encode('utf-8'))
    
    @staticmethod
    def get_iv(key, block_size=BLOCK_SIZE):
        """
        Create initialization vector based on AES key

        Args:
            key (bytes): block_size-lenght AES key
            block_size(int, optional): Default 16

        Returns:
            iv (bytes): initialization vector
                first block_size-length bytes from sha256(key)

        """
        key_h = hashlib.sha256()
        key_h.update(key)
        iv = key_h.digest()[:block_size]
        return iv
    
    @staticmethod
    def generate_RSA_keys(key_length=4096):
        """
        Generate pair of RSA keys

        Args:
            key_length (int, optional): Length of RSA keys. Default 4096. 
        
        Note:
            Saves private key in `private_key.pem`
            Saves public key in `public_key.pem`
            
            public_key: might be used in front end in javascript; used for encryption
            private_key: used for decryption

        """
        #Generate a public/ private key pair using 4096 bits key length (512 bytes)
        new_key = RSA.generate(4096, e=65537)

        #The private key in PEM format
        private_key = new_key.exportKey("PEM")

        #The public key in PEM Format
        public_key = new_key.publickey().exportKey("PEM")

        fd = open("private_key.pem", "wb")
        fd.write(private_key)
        fd.close()

        fd = open("public_key.pem", "wb")
        fd.write(public_key)
        fd.close()


cipher_text = Crypto.encrypt_AES('1234567890123456'.encode('utf-8'), '1234567890123456'.encode('utf-8'), "1234567890123456".encode('utf-8'))
