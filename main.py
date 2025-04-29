import rsaTools
import utils
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import cast


# --- CONFIG ---
MESSAGE = "Hello, RSA-secured server!"
private_key, public_key = rsaTools.generateRSAKeyPair()
cipher = rsaTools.encrypt(MESSAGE.encode(), public_key)
public_numbers = cast(rsa.RSAPublicNumbers, public_key.public_numbers())
n = public_numbers.n
e = public_numbers.e
# --- END CONFIG ---
#
# print(f"Modulus (n): {n}")
# print(f"Exponent (e): {e}")
#
# k = n.bit_length()
# print(f"K number (k): {k}")
#
# B = pow(2, k - 16)
#
# print(f"B number (B): {B}")

utils.generate_interval(public_key, private_key, MESSAGE)


# M = [2 * B, 3 * B - 1]
