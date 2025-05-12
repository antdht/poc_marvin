from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from numpy import ceil, floor
from typing import cast

import oracle
import utils


def marvin_break(ciphertext: bytes, oracle: oracle.Oracle):
    """
    Marvin's attack on RSA PKCS#1 v1.5 padding.
    Args:
        cipherText: The ciphertext to decrypt.
        oracle: The oracle used for the attack.
    Returns:
        The decrypted message.
    """
    public_key = oracle.getPublicKey()
    public_numbers = cast(rsa.RSAPublicNumbers, public_key.public_numbers())
    n = public_numbers.n
    e = public_numbers.e
    B = 2 ** (8 * ((n.bit_length() + 7) // 8) - 2)
    M = [(2 * B, 3 * B - 1)]  # List of tuples (intervals)

    c = int.from_bytes(ciphertext, byteorder="big")

    # decisionThreshold = utils.generatePKCSThresholdhold(oracle)
    decisionThreshold = 70000
    print("decisionThreshold:", decisionThreshold)

    i = 1
    s = 1
    while True:
        if i == 1:
            print("First iteration")
            # First iteration
            s = ceil(n / (3 * B))
            while True:
                craftedCipher = (c * (s**e)) % n
                if utils.isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                    break
                s += 1
        elif len(M) > 1:
            print("M > 1")
            s += 1
            while True:
                craftedCipher = (c * (s**e)) % n
                if utils.isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                    break
                s += 1
        else:
            print("one interval left")
            found = False
            (a, b) = M[0]
            r = ceil(2 * (b * s - 2 * B) / n)
            while True:
                s_min = ceil((2 * B + r * n) / b)
                s_max = ceil((3 * B + r * n) / a)
                s = s_min
                while s <= s_max:
                    craftedCipher = (c * (s**e)) % n
                    if utils.isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                        found = True
                        print("found a solution")
                        break
                    s += 1
                if found:
                    break
                r += 1

        # Narrowing down the set of solutions

        # FIX: I doubt the part with Max and Min is correct as the r must be a variable of the max/min
        newM = []
        print("Narrowing down the set of solutions")
        for a, b in M:
            print("n:", n, "\ns:", s, "\na:", a, "\nb:", b)
            r_min = (a * s - 3 * B + 1) // n
            print("numerator:", (a * s - 3 * B + 1))
            print("\n\nrmin:", r_min)
            r_max = -(-(b * s - 2 * B) // n)
            new_a = a
            new_b = b
            for r in range(r_min, r_max + 1):
                new_a = max(new_a, ceil((2 * B + r * n) / s))
                new_b = min(new_b, floor((3 * B - 1 + r * n) / s))
                if new_a <= new_b:
                    newM.append((new_a, new_b))
        M = newM
    if M[0][0] == M[0][1]:
        dirty_m = (M[0][0] * pow(s, -1, n)) % n
        # TODO: Implement the rest of the decryption process
        # We can in a first time compare m's bytes with the original message's bytes

        print("dirty decrypted message:", dirty_m)
        return "decrypted message"  # Placeholder for the decrypted message
    else:
        i += 1


if __name__ == "__main__":
    # Example usage
    sk = cast(
        rsa.RSAPrivateKey,
        rsa.generate_private_key(
            public_exponent=65537, key_size=1024, backend=default_backend()
        ),
    )

    oracle_instance = oracle.Oracle(sk)
    ciphertext = b"Private message lol"
    marvin_break(ciphertext, oracle_instance)
