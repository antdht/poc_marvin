from math import ceil
from typing import Tuple
import rsaTools as rsa
import time


def oracle(msg: bytes) -> Tuple[bool, float]:
    """
    Check PKCS1v15 padding, it is here to imit the case of a server,
    we will treat it like a black box piece of code.
    Args:
        msg: the message to check.
    Returns:
       bool: true if everything if fine, else false.
    """
    # PKCS#1 v1.5: 0x00 | 0x02 | PS…| 0x00
    start = time.time()
    if len(msg) < 11 or msg[0:2] != b"\x00\x02":
        end = time.time()
        response_time = end - start
        return False, response_time
    # find 0x00 separator after padding
    try:
        start = time.time()
        sep = msg.index(b"\x00", 2)
    except ValueError:
        end = time.time()
        response_time = end - start
        return False, response_time
    end = time.time()
    response_time = end - start
    return sep >= 10, response_time  # at least 8 bytes of PS


def find_valid_padding(ciphertext: bytes, n: int, e: int, B: int) -> int:
    """
    Test out padding by making call to the oracle
    Args:
        ciphertext: the message encrypted we try to find out
        n: the Modulus
        e: the exposure
    Returns:
        s: a valid padding
    """
    m = int.from_bytes(ciphertext, byteorder="big")
    s = ceil(n / (3 * B))
    k = (n.bit_length() + 7) // 8
    while True:
        c_prime = (m * pow(s, e, n)) % n
        c_prime_bytes = c_prime.to_bytes(k, byteorder="big")
        oracle_response = oracle(c_prime_bytes)
        if oracle_response[0] == True:
            print(f"Time: {oracle_response[1]}")
            return s
        s = s + 1


# --- CONFIG ---
MESSAGE = b"Hello, RSA-secured server!"


private_key, public_key = rsa.generateRSAKeyPair()


cipher = rsa.encrypt(MESSAGE, public_key)


public_numbers = public_key.public_numbers()
n = public_numbers.n
e = public_numbers.e

print(f"Modulus (n): {n}")
print(f"Exponent (e): {e}")

k = n.bit_length()
print(f"K number (k): {k}")

B = pow(2, k - 16)

print(f"B number (B): {B}")


padding = find_valid_padding(cipher, n, e, B)
print(f"padding: {padding}")

M = [2 * B, 3 * B - 1]
