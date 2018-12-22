from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16

class Crypto:
    """
    """
    def __init__(self):
        pass
    
    @staticmethod
    def encrypt_AES(key, iv, plain_text):
        """
        Encrypt plain_text with key and iv

        Args:
            key (bytes): 
            iv (bytes):
        
        Returns:
            cipher_text (bytes): encrypted data

        """
        encryption_suite = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = encryption_suite.encrypt(pad(plain_text, BLOCK_SIZE,  style='pkcs7'))
        return cipher_text
    
    @staticmethod
    def decrypt_AES(key, iv, cipher_text, block_size=BLOCK_SIZE):
        """
        Decryption AES

        Args:
            key (bytes):
            iv (bytes):
            cipher_text (bytes):

        Returns:
            plain_text (bytes):
        
        """
        iv = Crypto.get_iv(key)
        decryption_suite = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(decryption_suite.decrypt(data_to_decrypt), block_size)
        return decrypted_data


    @staticmethod
    def encrypt_RSA(publi_key, plain_text):
        """
        """
        pass
    
    @staticmethod
    def decrypt_RSA(private_key, cipher_text):
        """
        """
        encryption_suite = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        plain_text = encryption_suite.decrypt(cipher_text)
        return plain_text

    @staticmethod
    def get_random_key(block_size=BLOCK_SIZE):
        """
        """
        pass
    
    @staticmethod
    def get_iv(key, block_size=BLOCK_SIZE):
        """

        Args:
            key (bytes):
            block_size(int):

        Returns:

        """
        key_h = hashlib.sha256()
        key_h.update(key)
        return key_h.digest()[:block_size]
    
    @staticmethod
    def generate_RSA_keys():
        """
        Generate pair of RSA

        Returns:
            private_key ():
            public_key ():

        """
        pass


cipher_text = Crypto.encrypt_AES('1234567890123456'.encode('utf-8'), '1234567890123456'.encode('utf-8'), "1234567890123456".encode('utf-8'))
