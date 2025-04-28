import rsaTools
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import cast


def oracle_time_check(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> float:
    """
    Checks the time taken by the oracle to process the ciphertext.
    Args:
        ciphertext: the message to check.
    Returns:
        float: the time the oracle took to process the ciphertext.
    """
    start = time.monotonic_ns()
    rsaTools.decrypt(ciphertext, private_key)
    diff = time.monotonic_ns() - start
    return diff


# --- CONFIG ---
MESSAGE = b"Hello, RSA-secured server!"
private_key, public_key = rsaTools.generateRSAKeyPair()
cipher = rsaTools.encrypt(MESSAGE, public_key)
public_numbers = cast(rsa.RSAPublicNumbers, public_key.public_numbers())
n = public_numbers.n
e = public_numbers.e
# --- END CONFIG ---

print(f"Modulus (n): {n}")
print(f"Exponent (e): {e}")

k = n.bit_length()
print(f"K number (k): {k}")

B = pow(2, k - 16)

print(f"B number (B): {B}")


# padding = find_valid_padding(cipher, n, e, B)
# print(f"padding: {padding}")

M = [2 * B, 3 * B - 1]
