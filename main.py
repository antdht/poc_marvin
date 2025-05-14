from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import cast
import portion as P

import oracle
from utils import ceilDiv, floorDiv, isPKCSConforming, generatePKCSThresholdhold


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
    M = P.closed(2 * B, 3 * B - 1)

    c = int.from_bytes(ciphertext, byteorder="big")

    decisionThreshold = generatePKCSThresholdhold(oracle)
    # decisionThreshold = 55000
    print("decisionThreshold:", decisionThreshold)

    i = 1
    s = 1
    while M[0].lower != M[0].upper:
        if i == 1:
            print("First iteration")
            # First iteration
            s = ceilDiv(n, (3 * B))
            while True:
                craftedCipher = (c * pow(s, e, n)) % n
                if isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                    print("s:", s)
                    break
                s += 1
        elif len(M) > 1:
            print("M > 1")
            s += 1
            while True:
                print("s:", s)
                craftedCipher = (c * pow(s, e, n)) % n
                if isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                    break
                s += 1
        else:
            print("one interval left")
            found = False
            a = cast(int, M[0].lower)
            b = cast(int, M[0].upper)
            r = ceilDiv(2 * (b * s - 2 * B), n)
            while True:
                s_min = ceilDiv((2 * B + r * n), b)
                s_max = ceilDiv((3 * B + r * n), a)
                s = s_min
                while s <= s_max:
                    craftedCipher = (c * pow(s, e, n)) % n
                    if isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                        found = True
                        print("found a solution")
                        break
                    s += 1
                if found:
                    break
                r += 1

        # Narrowing down the set of solutions
        newM = P.empty()
        print("Narrowing down the set of solutions")
        for subInterval in M:
            a = cast(int, subInterval.lower)
            b = cast(int, subInterval.upper)
            r_min = ceilDiv((a * s - 3 * B + 1), n)
            r_max = floorDiv((b * s - 2 * B), n)
            new_a = a
            new_b = b
            for r in range(r_min, r_max + 1):
                new_a = max(new_a, ceilDiv((2 * B + r * n), s))
                new_b = min(new_b, floorDiv((3 * B - 1 + r * n), s))

                # NOTE: This verif should be useless if my math's understanding is correct
                if new_a <= new_b:
                    newM = newM | P.closed(new_a, new_b)
        print("newM size:", len(newM))
        M = newM
        i += 1

    dirty_m = (M[0].lower * pow(s, -1, n)) % n
    print("s:", s)
    print("n:", n)
    print("M[0]: ", M[0])
    print(
        "M[0] lower: ",
        M[0].lower.to_bytes((M[0].lower.bit_length() + 7) // 8, byteorder="big"),
    )
    # TODO: Implement the rest of the decryption process
    # We can in a first time compare m's bytes with the original message's bytes

    print("dirty decrypted message:", dirty_m)
    return "decrypted message"  # Placeholder for the decrypted message


if __name__ == "__main__":
    # Example usage
    sk = cast(
        rsa.RSAPrivateKey,
        rsa.generate_private_key(
            public_exponent=65537, key_size=512, backend=default_backend()
        ),
    )

    oracle_instance = oracle.Oracle(sk)
    ciphertext = b"Private"
    marvin_break(ciphertext, oracle_instance)
