import time
from typing import cast
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


class Oracle:
    def __init__(self, privateKey: rsa.RSAPrivateKey | None = None):
        if privateKey is None:
            # Generate a new RSA key pair if no private key is provided
            # NOTE: cast is used to tell the type checker "trust me, I know what I'm doing", as this old version of pyca/cryptography is not PEP 561 compliant

            self._sk = cast(
                rsa.RSAPrivateKey,
                rsa.generate_private_key(
                    public_exponent=65537, key_size=1024, backend=default_backend()
                ),
            )

        else:
            self._sk = privateKey

        self._pk = cast(rsa.RSAPublicKey, self._sk.public_key())

    def getPublicKey(self) -> rsa.RSAPublicKey:
        """
        Returns the public key.
        """
        return self._pk

    def decrypt(self, ciphertext: bytes):
        """
        Decrypts the given ciphertext using the private key.

        Args:
            ciphertext (bytes): The ciphertext to decrypt.
        """
        try:
            self._sk.decrypt(ciphertext, padding.PKCS1v15())
        except:
            pass

    def cheatDecrypt(self, ciphertext: bytes) -> bool:
        """
        Decrypts the given ciphertext using the private key and returns True if successful.

        Args:
            ciphertext (bytes): The ciphertext to decrypt.
        Returns:
            bool: True if decryption was successful, False otherwise.
        """
        try:
            self._sk.decrypt(ciphertext, padding.PKCS1v15())
            return True
        except:
            return False

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts the given plaintext using the public key.

        Args:
            plaintext (bytes): The plaintext to encrypt.
        Returns:
            bytes: The encrypted ciphertext.
        """
        return self._pk.encrypt(plaintext, padding.PKCS1v15())

    def time_check(self, ciphertext: bytes) -> float:
        """
        Checks the time taken by the oracle to process the ciphertext.
        Args:
            ciphertext: the message to check.
        Returns:
            float: the time the oracle took to process the ciphertext.
        """
        start = time.monotonic_ns()
        self.decrypt(ciphertext)
        return time.monotonic_ns() - start
