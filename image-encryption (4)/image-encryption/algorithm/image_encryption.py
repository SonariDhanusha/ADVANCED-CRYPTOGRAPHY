import os
import pathlib
import zlib

from Crypto import Random
from Crypto.Cipher import AES

from algorithm import aes, rsa

key_size: int = 128  # size of a key

# Default path for storing the keys, encrypted file and decrypted file.
project_path = "image_encryption"


def search_file_name(param_file, extension=False):
    """Returns file name from given path
    either with extension or without extension

    :param param_file:
    :param extension:
    :return project_file:
    """
    if not extension:
        project_file = pathlib.Path(param_file).stem

    else:
        project_file = os.path.basename(param_file)

    return project_file


def convert_str_byte(value: [str, bytes]) -> bytes:
    if isinstance(value, str):
        return value.encode(encoding='utf8')
    return value


def logic_fetch() -> bytes:
    logic: bytes = convert_str_byte("ImAgEeNcRyPtIoN")
    logic = zlib.compress(logic)
    return logic


def padding_text(string):
    """Returns the padded text for imageEncryption"""

    return string + (key_size - len(string) % key_size) * convert_str_byte(
        chr(key_size - len(string) % key_size))


def decoding_text(string):
    """Unpad the text and then returns it for imageDecryption"""

    return string[:-ord(string[len(string) - 1:])]


def encryption_check(logic, data_in_file):
    """Checks whether the file is already encrypted or not"""

    return data_in_file[:len(logic)] == logic


def param_file_fetch(param_file):
    """Returns the paramFile for storing the encrypted file"""

    project_file = os.path.basename(param_file)
    param_file = f"{project_path}/{project_file}.enc"
    return param_file


def image_encryption(param_file):
    """
    Read the given file in byte mode,
    get the AES key for imageEncryption,
    paddingText the text,
    generate the random initialization vector(iv) of 16 bytes,
    mode for imageEncryption : CBC,
    generate the cipher for imageEncryption using AES key, Mode, Iv,
    using cipher encrypt the plaintext and then add the Iv to it and value stored in cipher_text,
    before writing the cipher text, write the logic text for determining whether the file is encrypted or not,
    then write the cipher text.
    returns the appropriate massage

    :param param_file:
    :return message:
    """

    if not rsa.encryption_folder():
        rsa.create_encrypt_folder()

    read_file = open(param_file, "rb")
    plaintext = read_file.read()
    read_file.close()

    if encryption_check(logic_fetch(), plaintext):
        message = "File is already encrypted cannot encrypt again"
        return message

    key_session = aes.aes_key_fetch()
    raw_data = padding_text(plaintext)
    iv = Random.new().read(AES.block_size)
    mode = AES.MODE_CBC
    cipher = AES.new(key_session, mode, iv)
    cipher_text = iv + cipher.encrypt(raw_data)
    try:
        encrypted_file_path = param_file_fetch(param_file)
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(logic_fetch())
            encrypted_file.write(cipher_text)
            encrypted_file.close()
        message = f"File successfully encrypted & stored at :\n{project_path}"

    except Exception as e:
        message = "There is some error please check the selected file"
        print(e)

    return message


def image_decryption(param_file):
    """
    This function use for imageDecryption,
    First it will check whether the keys are there or not,
    if keys are present then it will read the file and
    check whether it is encrypted or not,
    if the file is encrypted then decrypt it using AES key
    and returns appropriate massage
    :param param_file:
    :return message:
    """

    logic = logic_fetch()
    if not (rsa.check_file() and aes.check_aes_key()):
        message = "Keys which are used for imageEncryption either deleted or corrupted, Cannot Decrypt"
        return message

    try:

        with open(param_file, "rb") as encrypted_file:
            cipher_text = encrypted_file.read()
            encrypted_file.close()

        if not encryption_check(logic, cipher_text):
            message = "Given file is not encrypted, please encrypt it first"
            return message

        cipher_text = cipher_text[len(logic):]
        key_session = aes.aes_key_fetch()
        iv = cipher_text[:AES.block_size]
        mode = AES.MODE_CBC
        cipher = AES.new(key_session, mode, iv)
        plaintext = decoding_text(cipher.decrypt(cipher_text[AES.block_size:]))

        project_file = search_file_name(param_file)
        with open(f"{project_path}/{project_file}", "wb") as decrypted_file:
            decrypted_file.write(plaintext)
            decrypted_file.close()

        os.remove(param_file)
        # Removes the encrypted file after completion of imageDecryption
        message = f"File successfully decrypted & stored at :\n{project_path}"

    except Exception as e:
        message = "There is some error please check the selected file"
        print(e)

    return message
