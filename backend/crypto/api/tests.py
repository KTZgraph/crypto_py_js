import unittest

from my_parametrized import expand
from crypto import Crypto
from crypto import CryptoException
from crypto import BLOCK_SIZE
# Create your tests here.

class TestCrypto(unittest.TestCase):
    """
    Tests for class Crypto

    crypto_py_js\backend\crypto\api>python -m unittest

    """

    aes_encrypt_data = [
        ["Ala ma kota.".encode('utf-8'), '0123456789012345'.encode('utf-8')],
        ["Ala ma kota.".encode('utf-8'), '0123456789012345'.encode('utf-8'), '0123456789012345'.encode('utf-8')],
        ["Ala ma kota.".encode('utf-8'), '0123456789012345'.encode('utf-8'), '0123456789012345'.encode('utf-8'), 16],
        ["Ala ma kota.".encode('utf-8'), '0123456789012345'.encode('utf-8'), '0123456789012345'.encode('utf-8'), 32],
        ["Ala ma kota.".encode('utf-8'), '0123456789012345'.encode('utf-8'), '0123456789012345'.encode('utf-8'), 64],
        ["Ala ma kota.".encode('utf-8')],
    ]
    @expand(aes_encrypt_data)
    def test_encrypt_AES(plain_text, key=None, iv=None, block_size=BLOCK_SIZE):
        """
        Tests function encrypt_AES with valid data - testing encryption with AES cipher 
        """
        cipher_text = Crypto.encrypt_AES(plain_text, key, iv, block_size)


    aes_encrypt_invalid_data = [
        ["Ala ma kota.", '0123456789012345'.encode('utf-8')],
        ["Ala ma kota.".encode('utf-8'), '0123456789012345', '0123456789012345'.encode('utf-8')],
        ["Ala ma kota.".encode('utf-8'), '0123456789012345'.encode('utf-8'), '0123456789012345', 16],
        ["Ala ma kota.".encode('utf-8'), '0123456789012345'.encode('utf-8'), '0123456789012345'.encode('utf-8'), 343],
        ["Ala ma kota.".encode('utf-8'), '0123456789012345'.encode('utf-8'), '0123456789012345'.encode('utf-8'), -1],
        ["Ala ma kota."]
    ]
    @expand(aes_encrypt_invalid_data)
    def test_encrypt_AES_invalid_data(plain_text, key=None, iv=None, block_size=BLOCK_SIZE):
        """
        Tests function encrypt_AES with invalid data - testing encryption with AES cipher 
        """
        raised = False

        try:
            Crypto.encrypt_AES(plain_text, key, iv, block_size)
            raise BaseException("test_encrypt_AES_invalid_data Failed ")
        except CryptoException:
            raised = True
        
        unittest.TestCase().assertTrue(expr = raised)


    aes_decrypt_data = [
        [b'\x0ciD\xd4\r\xd65fJ2\xbe8\xfa\xc8\xda\xa5', '0123456789012345'.encode('utf-8')],
        [b'\x0ciD\xd4\r\xd65fJ2\xbe8\xfa\xc8\xda\xa5', '0123456789012345'.encode('utf-8'), b'\x18J\xa4m\x814\x11r}\xa0\xdc\x9ed\x18k\xb9'],
        [b'\x0ciD\xd4\r\xd65fJ2\xbe8\xfa\xc8\xda\xa5', '0123456789012345'.encode('utf-8'), b'\x18J\xa4m\x814\x11r}\xa0\xdc\x9ed\x18k\xb9', 16],
        [ b'`\x97\xacQ\xbb\xd2\x12\x9d\x85\xe5\xff\xdbn\xd7\xd8\xf4\x80\x0c\x0f\xb6-\xfe\x13Fp\x83q\xe5\x04/\xfdl', '01234567890123450123456789012345'.encode('utf-8'), b'\x14c\xe1v\xa43\x8d\xb3\x9d]z\x15\x87*\xf2\xc2',32],
        [b'\xd46d\x0fo\x10f\\\x91I\x83\xfb\x9e\xf3\x19\xea\xdb$C\x98\x86&\xfb\xb2f\xdcE\xa5\xe4\xd6\x1a\xd0', b'0123456789012345',  b'0123456789012345', 32 ],
        [b'`\x97\xacQ\xbb\xd2\x12\x9d\x85\xe5\xff\xdbn\xd7\xd8\xf4\x80\x0c\x0f\xb6-\xfe\x13Fp\x83q\xe5\x04/\xfdl', b'01234567890123450123456789012345', b'\x14c\xe1v\xa43\x8d\xb3\x9d]z\x15\x87*\xf2\xc2', 32 ],
        [b'`\x97\xacQ\xbb\xd2\x12\x9d\x85\xe5\xff\xdbn\xd7\xd8\xf4\x80\x0c\x0f\xb6-\xfe\x13Fp\x83q\xe5\x04/\xfdl', b'01234567890123450123456789012345', None, 32 ],
    ]
    @expand(aes_decrypt_data)
    def test_decrypt_AES(cipher_text, key, iv=None, block_size=BLOCK_SIZE):
        """
        Tests function decrypt_AES with valid data
        """
        raised = False
        plain_text = Crypto.decrypt_AES(cipher_text, key, iv, block_size)
        if plain_text != 'Ala ma kota.'.encode('utf-8'):
            raised = True
        unittest.TestCase().assertFalse(expr = raised)


    aes_decrypt_data_invalid_data = [
        [b'\x0ciD\xd4\r\xd65fJ2\xbe8\xfa\xc8\xda\xa50', '0123456789012345'.encode('utf-8')],
        [b'\x0ciD\xd4\r\xd65fJ2\xbe8\xfa\xc8\xda\xa5', '01234567890123450'.encode('utf-8'), b'\x18J\xa4m\x814\x11r}\xa0\xdc\x9ed\x18k\xb9'],
        [b'\x0ciD\xd4\r\xd65fJ2\xbe8\xfa\xc8\xda\xa5', '0123456789012345'.encode('utf-8'), b'\x18J\xa4m\x814\x11r}\xa0\xdc\x9ed\x18k\xb90', 16],
        [b'`\x97\xacQ\xbb\xd2\x12\x9d\x85\xe5\xff\xdbn\xd7\xd8\xf4\x80\x0c\x0f\xb6-\xfe\x13Fp\x83q\xe5\x04/\xfdl', '01234567890123450123456789012345'.encode('utf-8'), b'\x14c\xe1v\xa43\x8d\xb3\x9d]z\x15\x87*\xf2\xc2',320],
        [b'\xd46d\x0fo\x10f\\\x91I\x83\xfb\x9e\xf3\x19\xea\xdb$C\x98\x86&\xfb\xb2f\xdcE\xa5\xe4\xd6\x1a\xd0', b'0123456789012345',  b'0123456789012345-', 32 ],
        [b'`\x97\xacQ\xbb\xd2\x12\x9d\x85\xe5\xff\xdbn\xd7\xd8\xf4\x80\x0c\x0f\xb6-\xfe\x13Fp\x83q\xe5\x04/\xfdl', b'01234567890123450123456789012345', b'\x14c\xe1v\xa43\x8d\xb3\x9d]z\x15\x87*\xf2\xc2-', 32 ],
        [b'`\x97\xacQ\xbb\xd2\x12\x9d\x85\xe5\xff\xdbn\xd7\xd8\xf4\x80\x0c\x0f\xb6-\xfe\x13Fp\x83q\xe5\x04/\xfdl', b'01234567890123450123456789012345', None, 320 ],
        [b'\x0ciD\xd4\r\xd65fJ2\xbe8\xfa\xc8\xda\xa50', '0123456789012345'],
        ['\x0ciD\xd4\r\xd65fJ2\xbe8\xfa\xc8\xda\xa5', '01234567890123450'.encode('utf-8'), b'\x18J\xa4m\x814\x11r}\xa0\xdc\x9ed\x18k\xb9'],
        [b'\x0ciD\xd4\r\xd65fJ2\xbe8\xfa\xc8\xda\xa5', '0123456789012345'.encode('utf-8'), b'\x18J\xa4m\x814\x11r}\xa0\xdc\x9ed\x18k\xb90', 16],
        [b'`\x97\xacQ\xbb\xd2\x12\x9d\x85\xe5\xff\xdbn\xd7\xd8\xf4\x80\x0c\x0f\xb6-\xfe\x13Fp\x83q\xe5\x04/\xfdl', '01234567890123450123456789012345', b'\x14c\xe1v\xa43\x8d\xb3\x9d]z\x15\x87*\xf2\xc2',320],
        [b'\xd46d\x0fo\x10f\\\x91I\x83\xfb\x9e\xf3\x19\xea\xdb$C\x98\x86&\xfb\xb2f\xdcE\xa5\xe4\xd6\x1a\xd0', b'0123456789012345',  b'0123456789012345-', '32' ],
        [b'`\x97\xacQ\xbb\xd2\x12\x9d\x85\xe5\xff\xdbn\xd7\xd8\xf4\x80\x0c\x0f\xb6-\xfe\x13Fp\x83q\xe5\x04/\xfdl', b'01234567890123450123456789012345', '\x14c\xe1v\xa43\x8d\xb3\x9d]z\x15\x87*\xf2\xc2', 32 ],
        [b'`\x97\xacQ\xbb\xd2\x12\x9d\x85\xe5\xff\xdbn\xd7\xd8\xf4\x80\x0c\x0f\xb6-\xfe\x13Fp\x83q\xe5\x04/\xfdl', b'01234567890123450123456789012345', 'None', 320 ],
        [b'`\x97\xacQ\xbb\xd2\x12\x9d\x85\xe5\xff\xdbn\xd7\xd8\xf4\x80\x0c\x0f\xb6-\xfe\x13Fp\x83q\xe5\x04/\xfdl', b'01234567890123450123456789012345', '', 320 ],
    ]
    @expand(aes_decrypt_data_invalid_data)
    def test_decrypt_AES_inavlid_data(cipher_text, key=None, iv=None, block_size=BLOCK_SIZE):
        """
        Tests function decrypt_AES with valid data
        """
        raised = False
        try:
            plain_text = Crypto.decrypt_AES(cipher_text, key, iv, block_size)
            if plain_text == "Ala ma kota.".encode('utf-8'):
                raised = True
        except BaseException:
            raised = True
        unittest.TestCase().assertTrue(expr = raised)

    def test_get_random_bytes(self,):
        """
        Test for function get_random_bytes() - raise error when returned random_bytes are the same
        """
        self.assertNotEqual(Crypto.get_random_bytes(), Crypto.get_random_bytes() )
    
    test_iv = [
        ["0123456789012345".encode('utf-8'), b'\x18J\xa4m\x814\x11r}\xa0\xdc\x9ed\x18k\xb9'],
        ["CipherPassword".encode('utf-8'), b"x`\x9b\xd1\xfd\xc5n\xf3\x8d\xd4%0\x82\xb1\xe4L"],
        ["ąęźćżłóńqldfsAES".encode('utf-8'), b"\xab\xf76\x05Vt\xa1T~\x87\xedX\x0bC\x1d\x08"],
    ]

    @expand(test_iv)
    def test_get_iv(key, iv):
        """
        Tests for functionget_iv with valid data, if get_iv(key) != iv raises Error
        """
        unittest.TestCase().assertEqual(Crypto.get_iv(key), iv)

    test_iv_invalid_data = [
        ["0123456789012345", b'\x18J\xa4m\x814\x11r}\xa0\xdc\x9ed\x18k\xb9'],
        ["CipherPassword".encode('utf-8'), "x`\x9b\xd1\xfd\xc5n\xf3\x8d\xd4%0\x82\xb1\xe4L"],
        ["ąęźćżłóńqldfsA".encode('utf-8'), b"\xab\xf76\x05Vt\xa1T~\x87\xedX"],
    ]
    @expand(test_iv_invalid_data)
    def test_get_iv_invalid_data(key, iv):
        """
        Tests for functionget_iv with valid data, if get_iv(key) != iv raises Error
        """
        raised = False
        try:
            if Crypto.get_iv(key) != iv:
                raised = True
        except BaseException:
            raised = True
        unittest.TestCase().assertTrue(expr = raised)

    # def test_encrypt_RSA(self,):
    #     """
    #     """
    #     pass

    # def test_decrypt_RSA(self,):
    #     """
    #     """
    #     pass

    
    # def test_generate_RSA_keys(self,):
    #     """
    #     """
    #     pass
