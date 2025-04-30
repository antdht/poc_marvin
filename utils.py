from typing import Tuple, cast
from cryptography.hazmat.primitives.asymmetric import rsa
import rsaTools
import time
import matplotlib.pyplot as plt
import numpy as np


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
    validPad = []
    invalidPad = []
    publicKey = cast(rsa.RSAPublicKey, private_key.public_key())
    # Start loop
    j = 2000000
    print(f"testing for {j} iterations")
    for i in range(j):
        ciphertext = rsaTools.encrypt(original_plain.encode(), publicKey)
        validPad.append(oracle_time_check(ciphertext, private_key))

        if i < j // 3:
            invalidCipher = ciphertext[1:]
            invalidPad.append(
                min(
                    oracle_time_check(invalidCipher, private_key),
                    oracle_time_check(invalidCipher, private_key),
                )
            )

        elif i < 2 * j // 3:
            invalidCipher = ciphertext
            invalidCipher = b"\x10\x10" + invalidCipher[:2]
            invalidPad.append(
                min(
                    oracle_time_check(invalidCipher, private_key),
                    oracle_time_check(invalidCipher, private_key),
                )
            )
        else:
            invalidCipher = ciphertext[1:]
            invalidPad.append(
                min(
                    oracle_time_check(invalidCipher, private_key),
                    oracle_time_check(invalidCipher, private_key),
                )
            )

    print("Valid padding records:")
    validPad.sort()
    validSize = len(validPad)
    validMean = sum(validPad) / validSize
    print(
        f"Smallest: {validPad[0]}\nMedian: {validPad[validSize // 2]}\nLargest: {validPad[-2]}\nMean: {validMean}\n"
    )

    counts, bin_edges = np.histogram(
        validPad, bins=100, range=(validPad[0], validPad[-1])
    )
    bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2
    plt.plot(bin_centers, counts, linestyle="-", marker="", color="blue")
    plt.yscale("log")
    plt.title("Log-Scale Distribution (Line Plot)")
    plt.xlabel("Value")
    plt.ylabel("Frequency (log scale)")
    plt.savefig("valid_log_double.png", dpi=300)
    plt.clf()

    print("Invalid padding records:")
    invalidPad.sort()
    invalidSize = len(invalidPad)
    invalidMean = sum(invalidPad) / invalidSize
    print(
        f"Smallest: {invalidPad[0]}\nMedian: {invalidPad[invalidSize // 2]}\nLargest: {invalidPad[-2]}\nMean: {invalidMean}\n"
    )
    counts2, bin_edges2 = np.histogram(
        invalidPad, bins=100, range=(invalidPad[0], invalidPad[-1])
    )
    bin_centers2 = (bin_edges2[:-1] + bin_edges2[1:]) / 2
    plt.plot(bin_centers2, counts2, linestyle="-", marker="", color="blue")
    plt.yscale("log")
    plt.title("Log-Scale Distribution (Line Plot)")
    plt.xlabel("Value")
    plt.ylabel("Frequency (log scale)")
    plt.savefig("unvalid_log_double.png", dpi=300)

    return (0.0, 1.0), (1.0, 2.0)
