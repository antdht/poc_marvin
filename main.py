from numpy import ceil, floor
import rsaTools
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import cast

import utils


def isPKCSConforming(
    cipherText: bytes, private_key: rsa.RSAPrivateKey, decisionThreshold: float
) -> bool:
    """
    Check if the ciphertext is PKCS conforming.
    Args:
        cipherText: The ciphertext to check.
        private_key: The private key used to call the oracle on decryption.
    Returns:
        True if the ciphertext is PKCS conforming, False otherwise.
    """
    # Takes longer than threshold -> PKCS conforming (no error raised)
    return utils.oracle_time_check(cipherText, private_key) > decisionThreshold


def marvin_break(cipherText: bytes, private_key: rsa.RSAPrivateKey):
    """
    Marvin's attack on RSA PKCS#1 v1.5 padding.
    Args:
        cipherText: The ciphertext to decrypt.
        private_key: The private key used to call the oracle on decryption.
    Returns:
        The decrypted message.
    """
    public_key = cast(rsa.RSAPublicKey, private_key.public_key())
    public_numbers = cast(rsa.RSAPublicNumbers, public_key.public_numbers())
    n = public_numbers.n
    e = public_numbers.e
    B = 2 ** (8 * ((n.bit_length() + 7) // 8) - 2)
    M = [(2 * B, 3 * B - 1)]  # List of tuples (intervals)

    decisionThreshold = 10  # TODO: CHANGE THIS WHEN METHOD IMPLEMENTED

    i = 1
    s = 1
    while len(M) > 1:
        if i == 1:
            # First iteration
            s = ceil(n / (3 * B))
            while True:
                craftedCipher = (cipherText * (s**e)) % n
                if isPKCSConforming(craftedCipher, private_key, decisionThreshold):
                    break
                s += 1
        elif len(M) > 1:
            s += 1
            while True:
                craftedCipher = (cipherText * (s**e)) % n
                if isPKCSConforming(craftedCipher, private_key, decisionThreshold):
                    break
                s += 1
        else:
            found = False
            (a, b) = M[0]
            r = ceil(2 * (b * s - 2 * B) / n)
            while True:
                s_min = ceil((2 * B + r * n) / b)
                s_max = ceil((3 * B + r * n) / a)
                s = s_min
                while s <= s_max:
                    craftedCipher = (cipherText * (s**e)) % n
                    if isPKCSConforming(craftedCipher, private_key, decisionThreshold):
                        found = True
                        break
                    s += 1
                if found:
                    break
                r += 1

        # Narrowing down the set of solutions

        # FIX: I doubt the part with Max and Min is correct as the r must be a variable of the max/min
        newM = []
        for a, b in M:
            r_min = ceil((a * s - 3 * B + 1) / n)
            r_max = floor((b * s - 2 * B) / n)
            for r in range(r_min, r_max + 1):
                new_a = max(a, ceil((2 * B + r * n) / s))
                new_b = min(b, floor((3 * B - 1 + r * n) / s))
                if new_a <= new_b:
                    newM.append((new_a, new_b))
        M = newM
    if M[0][0] == M[0][1]:
        m = (M[0][0] * pow(s, -1, n)) % n
        # TODO: Implement the rest of the decryption process
        # We can in a first time compare m's bytes with the original message's bytes

        # WARN: DONT ACTUALLY RETURN THIS
        return "decrypted message"  # Placeholder for the decrypted message
    else:
        i += 1


if __name__ == "__main__":
    # --- CONFIG ---
    MESSAGE = "Hello, RSA-secured server!"
    private_key, public_key = rsaTools.generateRSAKeyPair()
    cipher = rsaTools.encrypt(MESSAGE.encode(), public_key)
