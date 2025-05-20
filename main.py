from cryptography.hazmat.primitives.asymmetric import rsa
from typing import cast
import portion as P

import oracle
from utils import ceilDiv, floorDiv, integer_to_bytes, isPKCSConforming, PKCS1_decode


def marvin_break(ciphertext: bytes, oracle: oracle.Oracle) -> bytes:
    """
    Marvin's attack on RSA PKCS#1 v1.5 padding.
    Args:
        cipherText: The ciphertext to decrypt.
        oracle: The oracle used for the attack.
    Returns:
        The bytes of the decrypted message.
    """
    public_key = oracle.getPublicKey()
    public_numbers = cast(rsa.RSAPublicNumbers, public_key.public_numbers())
    n = public_numbers.n
    e = public_numbers.e
    B = 2 ** (8 * ((n.bit_length() // 8) - 2))
    M = P.closed(2 * B, 3 * B - 1)

    c = int.from_bytes(ciphertext, byteorder="big")

    # decisionThreshold = generatePKCSThresholdhold(oracle)
    decisionThreshold = 55000

    s = ceilDiv(n, (3 * B))
    i = 1
    while True:
        # Step 2.A
        if i == 1:
            # First iteration
            while True:
                craftedCipher = (c * pow(s, e, n)) % n
                if isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                    break
                s += 1
        # Step 2.B
        elif len(M) > 1:
            s += 1
            while True:
                craftedCipher = (c * pow(s, e, n)) % n
                if isPKCSConforming(craftedCipher, oracle, decisionThreshold):
                    break
                s += 1
        # Step 2.C
        else:
            found = False
            a = cast(int, M[0].lower)
            b = cast(int, M[0].upper)
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

        # Step 3: Narrowing down the set of solutions
        newM = P.empty()
        r_min = 0
        r_max = 0
        for subInterval in M:
            a = cast(int, subInterval.lower)
            b = cast(int, subInterval.upper)
            r_min = ceilDiv(a * s - 3 * B + 1, n)
            r_max = ceilDiv(b * s - 2 * B, n)
            for r in range(r_min, r_max + 1):
                new_a = max(a, ceilDiv(2 * B + r * n, s))
                new_b = min(b, floorDiv(3 * B - 1 + r * n, s))

                newM = newM | P.closed(new_a, new_b)
        M = newM

        # Step 4: Computing the final message
        if len(M) == 1 and M[0].lower == M[0].upper:
            break
        i += 1

    a = M[0].lower
    m = a % n
    m_bytes = integer_to_bytes(m)
    assert not m_bytes.startswith(b"\x00\x02"), (
        "Invalid final padding",
        m_bytes[:10].hex(),
    )

    return m_bytes


if __name__ == "__main__":
    # Example usage
    oracle_instance = oracle.Oracle()
    ciphertext = oracle_instance.encrypt(
        b"Marvin is bleichenbacher exploiting side channels !"
    )
    discovered = marvin_break(ciphertext, oracle_instance)
    decoded = PKCS1_decode(discovered)
    print("\ndecoded:", decoded)
