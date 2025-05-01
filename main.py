import rsaTools
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import cast


def marvin_break(cipherText: bytes, private_key: rsa.RSAPrivateKey):
    public_key = cast(rsa.RSAPublicKey, private_key.public_key())
    public_numbers = cast(rsa.RSAPublicNumbers, public_key.public_numbers())
    n = public_numbers.n
    e = public_numbers.e
    pass


if __name__ == "__main__":
    # --- CONFIG ---
    MESSAGE = "Hello, RSA-secured server!"
    private_key, public_key = rsaTools.generateRSAKeyPair()
    cipher = rsaTools.encrypt(MESSAGE.encode(), public_key)
