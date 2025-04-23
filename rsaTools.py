from typing import Tuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def generateRSAKeyPair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generates a pair of RSA keys.
    Returns:
        private_key: The generated private key.
        public_key: The generated public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=1024, backend=default_backend()
    )

    public_key = private_key.public_key()  # type: ignore

    return private_key, public_key


def encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypts a message using the public key.
    Args:
        plaintext: The message to encrypt.
        public_key: The public key to use for encryption.
    Returns:
        ciphertext: The encrypted message.
    """
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypts a message using the private key.
    Args:
        ciphertext: The encrypted message to decrypt.
        private_key: The private key to use for decryption.
    Returns:
        plaintext: The decrypted message.
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


if __name__ == "__main__":
    private_key, public_key = generateRSAKeyPair()
    print("Private Key:", private_key)
    print("Public Key:", public_key)
    message = b"Hello, this is a secret message."
    print("Original Message:", message)
    encrypted_message = encrypt(message, public_key)
    print("Encrypted Message:", encrypted_message)
    decrypted_message = decrypt(encrypted_message, private_key)
    print("Decrypted Message:", decrypted_message)
