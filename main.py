from collections import namedtuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import cast

import oracle
from utils import ceilDiv, floorDiv, integer_to_bytes, isPKCSConforming, PKCS1_decode


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


# Step 3.
def update_intervals(M, s, B, n):
    """
    After found the s value, compute the new list of intervals
    """

    M_new = []

    for a, b in M:
        r_lower = ceilDiv(a * s - 3 * B + 1, n)
        r_upper = ceilDiv(b * s - 2 * B, n)

        for r in range(r_lower, r_upper):
            lower_bound = max(a, ceilDiv(2 * B + r * n, s))
            upper_bound = min(b, floorDiv(3 * B - 1 + r * n, s))

            interval = Interval(lower_bound, upper_bound)

            M_new = safe_interval_insert(M_new, interval)

    M.clear()

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
    B = 2 ** (8 * ((n.bit_length() // 8) - 2))
    M = [Interval(2 * B, 3 * B - 1)]

    c = int.from_bytes(ciphertext, byteorder="big")

    # decisionThreshold = generatePKCSThresholdhold(oracle)
    decisionThreshold = 55000
    print("decisionThreshold:", decisionThreshold)

    s = ceilDiv(n, (3 * B))
    print("s:", s)
    i = 1
    while True:
        # Step 2.A
        if i == 1:
            print("First iteration")
            # First iteratio
            while True:
                craftedCipher = (c * pow(s, e, n)) % n
                if isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                    break
                s += 1
        # Step 2.B
        elif len(M) > 1:
            print("M > 1")
            s += 1
            while True:
                craftedCipher = (c * pow(s, e, n)) % n
                if isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                    break
                s += 1
        # Step 2.C
        else:
            print("M == 1")
            found = False
            a = M[0].lower_bound
            b = M[0].upper_bound
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
        M = update_intervals(M, s, B, n)
        if len(M) != 1:
            print("M size:", len(M))
        else:
            x = M[0].lower_bound
            y = M[0].upper_bound
            print(f"range: {y - x}")

        # Step 4
        if len(M) == 1 and M[0].lower_bound == M[0].upper_bound:
            break
        i += 1

    a = M[0].lower_bound
    # m = (a * pow(s, -1, n)) % n
    m = a % n
    am_bytes = integer_to_bytes(m)
    # print("n:", n)
    # print("a:", a)
    # print("m_bytes:", m_bytes)
    print("alterned m_bytes:", am_bytes)
    assert not am_bytes.startswith(b"\x00\x02"), (
        "Warning: invalid padding:",
        am_bytes[:10].hex(),
    )

    return am_bytes


if __name__ == "__main__":
    # Example usage
    sk = cast(
        rsa.RSAPrivateKey,
        rsa.generate_private_key(
            public_exponent=65537, key_size=1024, backend=default_backend()
        ),
    )

    oracle_instance = oracle.Oracle(sk)
    ciphertext = oracle_instance.encrypt(b"Private message")
    discovered = marvin_break(ciphertext, oracle_instance)
    decoded = PKCS1_decode(discovered)
    print("decoded:", decoded)
