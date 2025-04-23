from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import base64
import rsaTools as rsa
import requests

# --- CONFIG ---
GET_PUBLIC_KEY_URL = "http://localhost:8000/public-key"
POST_MESSAGE_URL = "http://localhost:8000/decrypt"
MESSAGE = b"Hello, RSA-secured server!"
# ---------------

# Step 1: Get the public key from server
response = requests.get(GET_PUBLIC_KEY_URL)
pem_str = response.json()["public_key"]

# Safe load
public_key = serialization.load_pem_public_key(
    pem_str.encode("utf-8"), backend=default_backend()
)
assert isinstance(public_key, RSAPublicKey), "Invalid public key type"
print("Public Key:", public_key)

public_numbers = public_key.public_numbers()
n = public_numbers.n
e = public_numbers.e

print(f"Modulus (n): {n}")
print(f"Exponent (e): {e}")

k = n.bit_length()
print(f"K number (k): {k}")

B = pow(2, k - 16)

print(f"B number (B): {B}")


def find_valid_padding(ciphertext: bytes):
    pass
