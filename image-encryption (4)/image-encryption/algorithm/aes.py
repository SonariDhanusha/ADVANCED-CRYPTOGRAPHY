import hashlib
import os

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from algorithm import rsa

# path for storing the AES key
AESKeyPath = "image_encryption/public_private_keys/aes_key.txt"


def convert_str_byte(value: [str, bytes]) -> bytes:
    if isinstance(value, str):
        return value.encode(encoding='utf8')
    return value


def check_aes_key():
    """
    Returns True if AES key already exist else False
    """
    return os.path.isfile(AESKeyPath) and os.stat(AESKeyPath).st_size != 0


def aes_key_generated():
    """
    Generate the random bytes of 128 length and returns it
    """
    return get_random_bytes(128)


def aes_encryption(key_session):
    """
    This function is use for encrypt the AES key using RSA public key,
    Make a file, write the encrypted AES key
    And then store it at the default path for AES key
    :param key_session:
    """
    public_key = rsa.public_key()
    public_key = RSA.importKey(public_key)
    public_key = PKCS1_OAEP.new(public_key)

    encrypted_aes_key = public_key.encrypt(key_session)

    access_aes_key = open(AESKeyPath, "wb")
    access_aes_key.write(encrypted_aes_key)
    access_aes_key.close()


def aes_decryption():
    """
    This function used for decrypt the AES key using RSA private key,
    and returns the decrypted AES key.
    :return AES key:
    """

    if not check_aes_key():
        raise FileNotFoundError

    private_key = rsa.private_key()
    private_key = RSA.importKey(private_key)
    private_key = PKCS1_OAEP.new(private_key)

    read_aes_key = open(AESKeyPath, "rb")
    aes_key = read_aes_key.read()

    return private_key.decrypt(aes_key)


def aes_key_fetch():
    """Returns the AES key"""

    if not (check_aes_key() and rsa.check_file()):
        key = aes_key_generated()
        aes_encryption(key)

    aes_key = aes_decryption()

    return hashlib.sha256(convert_str_byte(aes_key)).digest()
