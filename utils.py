from random import randint
import oracle


def isPKCSConforming(
    cipherText: bytes, oracle: oracle.Oracle, decisionThreshold: float
) -> bool:
    """
    Check if the ciphertext is PKCS conforming.
    Args:
        cipherText: The ciphertext to check.
        oracle: The oracle object used to check the ciphertext.
        decisionThreshold: The threshold for deciding if the ciphertext is PKCS conforming.
    Returns:
        True if the ciphertext is PKCS conforming, False otherwise.
    """
    # Takes longer than threshold -> PKCS conforming (no error raised)
    return oracle.time_check(cipherText) > decisionThreshold


def gen_str(lengt_index: int) -> bytes:
    """
    Generate a string encoded into bytes
    Args:
        lengt_index: the lengt (this value will be multiply by 4)
    Returns:
        an encoded str
    """
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

    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    chars_mod = len(charset)
    message = ""

    for _ in range(lengt_index * 4):
        base = primes[randint(0, len(primes) - 1)]
        exp = randint(2, 3)
        message += charset[pow(base, exp, chars_mod)]
    return message.encode()


def str_fuzzing(text: bytes) -> bytes:
    """
    Fuzz the input bytes by randomly modifying a few characters.
    Args:
        text: The byte string to fuzz.
    Returns:
        A fuzzed version of the byte string.
    """
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

    charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    chars_mod = len(charset)
    original_length = len(text)

    for _ in range(3):
        base = primes[randint(0, len(primes) - 1)]
        exp = randint(2, 3)
        index = pow(base, exp, original_length)
        replacement = bytes([charset[pow(base, exp, chars_mod)]])
        text = text[:index] + replacement + text[index + 1 :]

    return text


def generatePKCSThresholdhold(oracle: oracle.Oracle) -> float:
    """
    Generate interval for side chanel attack
    Args:
        oracle: The oracle on which to generate the interval.
    Returns:
        The threshold to classify a ciphertext as PKCS conforming or not PKCS conforming.
    """
    # Setting up the fuzzer

    validPad = []
    invalidPad = []
    byte_text = b"OMG, super secret message, please don't hack me!"

    # Start loop
    j = 200000
    print(f"testing for {j} iterations")
    counter = 0
    for i in range(j):
        if i == (j // 28) * counter:
            counter += 1
            byte_text = gen_str(counter)
            print(f"We reached {i / j * 100:0,.2f}%")

        byte_text = str_fuzzing(byte_text)
        ciphertext = oracle.encrypt(byte_text)
        validPad.append(
            min(
                oracle.time_check(ciphertext),
                oracle.time_check(ciphertext),
            )
        )

        if i % 3:
            invalidCipher = ciphertext[1:]
            invalidPad.append(
                min(
                    oracle.time_check(invalidCipher),
                    oracle.time_check(invalidCipher),
                )
            )

        elif (i + 1) % 3:
            invalidCipher = ciphertext
            invalidCipher = b"\x10\x10" + invalidCipher[:2]
            invalidPad.append(
                min(
                    oracle.time_check(invalidCipher),
                    oracle.time_check(invalidCipher),
                )
            )
        else:
            invalidCipher = ciphertext[1:]
            invalidPad.append(
                min(
                    oracle.time_check(invalidCipher),
                    oracle.time_check(invalidCipher),
                )
            )

    invalidPad.sort()
    invalidSize = len(invalidPad)
    invalidMean = sum(invalidPad) / invalidSize
    distance = invalidMean + (validPad[0] - invalidMean) * 2 / 3
    return distance
