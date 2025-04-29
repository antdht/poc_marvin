import re
from typing import Tuple, cast, Union
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


def generateRSAKeyPair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generates a pair of RSA keys.
    Returns:
        private_key: The generated private key.
        public_key: The generated public key.
    """
    # NOTE: cast is used to tell the type checker "trust me, I know what I'm doing", as this old version of pyca/cryptography is not PEP 561 compliant
    private_key = cast(
        rsa.RSAPrivateKey,
        rsa.generate_private_key(
            public_exponent=65537, key_size=1024, backend=default_backend()
        ),
    )

    public_key = cast(rsa.RSAPublicKey, private_key.public_key())

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
    ciphertext = cast(
        bytes,
        public_key.encrypt(
            plaintext,
            padding.PKCS1v15(),
        ),
    )
    return ciphertext


def decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> Union[bytes, None]:
    """
    Decrypts a message using the private key.
    Args:
        ciphertext: The encrypted message to decrypt.
        private_key: The private key to use for decryption.
    Returns:
        plaintext: The decrypted message.
    """
    try:
        plaintext = cast(
            bytes,
            private_key.decrypt(
                ciphertext,
                padding.PKCS1v15(),
            ),
        )
        return plaintext
    except:
        return None
