from typing import Tuple, cast
from cryptography.hazmat.primitives.asymmetric import rsa
import rsaTools
from random import randint
import time


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


def generate_interval(
    private_key: rsa.RSAPrivateKey, original_plain: str
) -> Tuple[Tuple[float, float], Tuple[float, float]]:
    """
    Generate interval for side chanel attack
    Args:
        publicKey: RSAPublicKey for encrypting cyphertexts
        original_plain: the plain we are attacking, we will random fuzze
    Returns:
        Intervals of true and false
    """
    # Setting up the fuzzer
    original_length = len(original_plain)
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    chars_mod = 62
    primes = [
        101,
        103,
        107,
        109,
        113,
        127,
        131,
        137,
        139,
        149,
        151,
        157,
        163,
        167,
        173,
        179,
        181,
        191,
        193,
        197,
    ]

    base = primes[randint(0, 19)]
    validPad = []
    unvalidPad = []
    publicKey = cast(rsa.RSAPublicKey, private_key.public_key())
    # Start loop
    j = 20000
    print(f"testing for {j} iterations")
    for i in range(j):
        ciphertext = rsaTools.encrypt(original_plain.encode(), publicKey)
        validPad.append(oracle_time_check(ciphertext, private_key))

        if i < 5:
            ciphertext_but_invalid = ciphertext[1:]
            unvalidPad.append(oracle_time_check(ciphertext_but_invalid, private_key))

        elif i < 12:
            ciphertext_but_invalid = ciphertext
            ciphertext_but_invalid = b"\x10\x10" + ciphertext_but_invalid[:2]
            unvalidPad.append(oracle_time_check(ciphertext_but_invalid, private_key))
        else:
            ciphertext_but_invalid = ciphertext[::-1]
            unvalidPad.append(oracle_time_check(ciphertext_but_invalid, private_key))

    print("Valid padding records:")
    validPad.sort()
    validSize = len(validPad)
    validMean = sum(validPad) / validSize
    print(
        f"Smallest: {validPad[0]}\nMedian:{validPad[validSize // 2]}\nLargest: {validPad[-2]}\nMean: {validMean}\n"
    )

    print("Invalid padding records:")
    unvalidPad.sort()
    unvalidSize = len(unvalidPad)
    unvalidMean = sum(unvalidPad) / unvalidSize
    print(
        f"Smallest: {unvalidPad[0]}\nMedian:{unvalidPad[unvalidSize // 2]}\nLargest: {unvalidPad[-2]}\nMean: {unvalidMean}\n"
    )
    return (0.0, 1.0), (1.0, 2.0)
