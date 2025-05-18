from collections import namedtuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import cast
import portion as P

import oracle
from utils import ceilDiv, floorDiv, isPKCSConforming


Interval = namedtuple("Interval", ["lower_bound", "upper_bound"])


def safe_interval_insert(M_new: list, interval: Interval):
    """
    Deal with interval overlaps when adding a new one to the list
    """

    for i, (a, b) in enumerate(M_new):

        # overlap found, construct the larger interval
        if (b >= interval.lower_bound) and (a <= interval.upper_bound):
            lb = min(a, interval.lower_bound)
            ub = max(b, interval.upper_bound)

            M_new[i] = Interval(lb, ub)
            return M_new

    # no overlaps found, just insert the new interval
    M_new.append(interval)

    return M_new


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
    M = [(2 * B, 3 * B - 1)]

    c = int.from_bytes(ciphertext, byteorder="big")

    # decisionThreshold = generatePKCSThresholdhold(oracle)
    decisionThreshold = 55000
    print("decisionThreshold:", decisionThreshold)

    s = 1
    i = 1
    while True:
        if i == 1:
            print("First iteration")
            # First iteration
            s = ceilDiv(n, (3 * B))
            while True:
                craftedCipher = (c * pow(s, e, n)) % n
                if isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                    break
                s += 1
        elif len(M) > 1:
            print("M > 1")
            s += 1
            while True:
                craftedCipher = (c * pow(s, e, n)) % n
                if isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                    break
                s += 1
        else:
            print("one interval left")
            found = False
            a = cast(int, M[0][0])
            b = cast(int, M[0][1])
            r = ceilDiv(2 * (b * s - 2 * B), n)
            while True:
                s_min = ceilDiv((2 * B + r * n), b)
                s_max = ceilDiv((3 * B + r * n), a)
                s = s_min
                while s < s_max:
                    craftedCipher = (c * pow(s, e, n)) % n
                    if isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                        found = True
                        break
                    s += 1
                if found:
                    break
                r += 1

        # Narrowing down the set of solutions
        print(f"s: {s}")
        newM = []
        r_min = 0
        r_max = 0
        for a, b in M:
            r_min = ceilDiv((a * s - 3 * B + 1), n)
            r_max = floorDiv((b * s - 2 * B), n)
            for r in range(r_min, r_max + 1):
                new_a = max(a, ceilDiv((2 * B + r * n), s))
                new_b = min(b, floorDiv((3 * B - 1 + r * n), s))

                # NOTE: This verif should be useless if my math's understanding is correct

                # if new_a <= new_b:
                interval = Interval(new_a, new_b)
                newM = safe_interval_insert(newM, interval)
        if len(newM) != 1:
            print("newM size:", len(newM))
            # print("newM:", newM)
            # print(f"r_min: {r_min}, r_max: {r_max}")
        else:
            x = cast(int, M[0][0])
            y = cast(int, M[0][1])
            print(f"range: {y - x}")
        M = newM
        if len(M) == 1 and M[0][0] == M[0][1]:
            break
        i += 1

    a = cast(int, M[0][0])
    m = (a * pow(s, -1, n)) % n
    m_bytes = m.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    m = a % n
    am_bytes = m.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    print("n:", n)
    print("a:", a)
    print("m_bytes:", m_bytes)
    print("alterned m_bytes:", am_bytes)
    if not m_bytes.startswith(b"\x00\x02"):
        print("Warning: invalid padding:", m_bytes[:10].hex())

    sep = m_bytes.find(b"\x00", 2)
    assert sep != -1, "Invalid PKCS#1 v1.5 padding structure"
    plaintext = m_bytes[sep + 1 :]
    return plaintext


if __name__ == "__main__":
    # Example usage
    sk = cast(
        rsa.RSAPrivateKey,
        rsa.generate_private_key(
            public_exponent=65537, key_size=512, backend=default_backend()
        ),
    )

    oracle_instance = oracle.Oracle(sk)
    ciphertext = oracle_instance.encrypt(b"Private")
    marvin_break(ciphertext, oracle_instance)
