import os
import random
from ctypes import *
from pathlib import Path

from Crypto.PublicKey import RSA

user_path = "./image_encryption"  # path of user directory
store_key = "{}/public_private_keys".format(user_path)  # keys will be stored in this path


def check_keys():
    """Returns True if keys folder/directory exist else False"""

    return Path(store_key).is_dir()


def check_file():
    """Returns True if both the key files(public key file and private key file) are exist else False"""

    public_key_path = f"{store_key}/public key.pem"
    private_key_path = f"{store_key}/private key.pem"
    public_key_check = os.path.isfile(public_key_path) and os.stat(public_key_path).st_size != 0
    private_key_check = os.path.isfile(private_key_path) and os.stat(private_key_path).st_size != 0

    return public_key_check and private_key_check


def create_folder():
    """
    Creates the keys folder/directory at mentioned path and hides it so,
    """

    Path(store_key).mkdir(parents=True, exist_ok=True)
    file_attribute_hidden = 0x02
    try:
        windll.kernel32.SetFileAttributesW(store_key, file_attribute_hidden)
    except Exception as storage_error:
        print(storage_error)


def encryption_folder():
    """
    Returns True if the default folder/directory exists else False
    """

    return Path(user_path).is_dir()


def create_encrypt_folder():
    """
    Creates the default folder/directory at the mentioned path
    """

    try:
        Path(user_path).mkdir(parents=True, exist_ok=True)
    except Exception as enFolderNotFound:
        print(enFolderNotFound)


def generate_prime_num(lower_limit, upper_limit):
    """
    Generates prime numbers for a given range using Sieve of Eratosthenes algorithm
    :param lower_limit: int for lower limit of range
    :param upper_limit: int for  upper limit of range
    :return: list of prime numbers
    """
    prime_nums = []
    is_prime = [True] * (upper_limit + 1)
    is_prime[0] = is_prime[1] = False  # 0 and 1 are not prime numbers

    for number in range(lower_limit, int(upper_limit ** 0.5) + 1):
        if is_prime[number]:
            prime_nums.append(number)
            for multiple in range(number * number, upper_limit + 1, number):
                is_prime[multiple] = False

    # Add the remaining primes greater than sqrt(limit)
    for number in range(int(upper_limit ** 0.5) + 1, upper_limit + 1):
        if is_prime[number]:
            prime_nums.append(number)

    return prime_nums


def choosing_best_prime(length_of_bit):
    """To check whether the random number is the best choice for prime.
    This function will divide random number by all pre generated primes,
    if the number is divided by any of the pre generated prime then it will
    take another random number and check again.
    if number is not divide by any pre generated prime then simply returns that number
    :param length_of_bit:
    :return best choice for prime number of length_of_bit:
    """
    while True:
        # random number range should be from 2^1023 + 1 to 2^1024 - 1
        select_prime = random.randrange(2 ** (length_of_bit - 1) + 1, 2 ** length_of_bit - 1)

        for divisor_num in generate_prime_num(2, 350):
            if select_prime % divisor_num == 0:
                break
        else:
            return select_prime


def primality_test_3(select_prime):
    """Primality test 3 for checking whether the number is prime or not
    :param select_prime:
    :return True for probably prime number otherwise False:
    """
    # find right_shift such that n = 2^u * right_shift + 1
    right_shift = select_prime - 1
    primality_number = 0

    while right_shift % 2 == 0:
        # divide by two is similar to shift 1 right side
        right_shift >>= 1  # right_shift = right_shift/2
        primality_number += 1
    assert (2 ** primality_number * right_shift == select_prime - 1)  # 2^u * right_shift == n - 1

    def comp_number(number):
        """This function to check miller-rabin conditions whether the number is composite or not:
            (i) a^right_shift mod(n) != 1 Returns True
            (i) i in 0 to u (here primality_number) checking:
                a^(2^i * right_shift) mod(n) != (n - 1) Returns True
        :param number:
        """
        if pow(number, right_shift, select_prime) == 1:
            return False

        for i in range(primality_number):
            if pow(number, 2 ** i * right_shift, select_prime) == (select_prime - 1):
                return False

        return True

    # generally in miller-rabin algorithm for finding
    # whether the number is prime or not 20 iteration perform
    iterations = 20
    # Checks 20 times whether the random number passes miller-rabin condition or not
    for _ in range(iterations):
        check = random.randrange(2, select_prime - 2)  # range should be 2 to (select_prime - 2)
        if comp_number(check):
            return False

    return True


def get_prime_num():
    """This function returns probably prime number.
    first it generates the random integer using choosing_bestPrime function
    then it will check whether the number is passed by miller-rabin algorithm
    if it returns true then this function returns the probably prime number of length 1024
    """
    while True:
        length_of_bit = 1024
        select_prime = choosing_best_prime(length_of_bit)

        if not primality_test_3(select_prime):
            continue
        else:
            return select_prime


def generate_two_keys():
    """Generate public key and private key pair
    public key is a pair of e (which is co-prime of n) and
    n(which is multiplication of two prime numbers (x,y))

    private key is a pair of d(which is multiplicative inverse of e) and n

    :return (public key, private key):
    """
    x = get_prime_num()
    y = get_prime_num()

    n = x * y
    phi = (x - 1) * (y - 1)

    while True:
        e = random.randrange(1, phi)
        if euclidean(e, phi) == 1:
            break

    d = eea(e, phi)

    return (e, n), (d, n)


def euclidean(dividend, divisor):
    while divisor != 0:
        quotient = dividend % divisor
        dividend = divisor
        divisor = quotient
    return dividend


def eea(dividend, num):  # Calculates inverse modular of two integers
    if euclidean(dividend, num) != 1:
        return None

    p1, p2, p3 = 1, 0, dividend
    o1, o2, o3 = 0, 1, num

    while o3 != 0:
        quot = p3 // o3
        o1, o2, o3, p1, p2, p3 = (p1 - quot * o1), (p2 - quot * o2), (p3 - quot * o3), o1, o2, o3

    return p1 % num


def keys_generated():
    """
    Construct the RSA key pair from generated public and private key
    and then, export the key pair in PEM format
    :return public key, private key:
    """
    _public_key, _private_key = generate_two_keys()

    e, n = _public_key
    d, a = _private_key

    _public_key = RSA.construct((n, e))
    _private_key = RSA.construct((n, e, d))

    _private_key = _private_key.exportKey("PEM")
    _public_key = _public_key.exportKey("PEM")

    return _public_key, _private_key


def store_keys():
    """
    This function will create the default directory and keys directory if they are not exist
    and then, storing the keys at default path
    """

    if not encryption_folder():
        create_encrypt_folder()
        create_folder()

    if not check_keys():
        create_folder()

    try:
        _public_key, _private_key = keys_generated()
        access_pub_key = open(f"{store_key}/public key.pem", "wb")
        access_pub_key.write(_public_key)
        access_pub_key.close()

        access_private_key = open(f"{store_key}/private key.pem", "wb")
        access_private_key.write(_private_key)
        access_private_key.close()

    except Exception as keysNotfound:
        print(keysNotfound)


def public_key():  # Public key returns

    pub_key_path = f"{store_key}/public key.pem"
    if not check_file():
        store_keys()

    read_pub_key = open(pub_key_path, "rb")
    _public_key = read_pub_key.read()
    read_pub_key.close()
    return _public_key


def private_key():  # Private key returns

    private_key_path = f"{store_key}/private key.pem"
    if not check_file():
        store_keys()

    read_private_key = open(private_key_path, "rb")
    _private_key = read_private_key.read()
    read_private_key.close()
    return _private_key
