import rsaTools as rsa


def testRsa():
    """
    Test the RSA encryption and decryption process.
    """

    private_key, public_key = rsa.generateRSAKeyPair()
    message = b"Hello, this is a secret message."
    encrypted_message = rsa.encrypt(message, public_key)
    decrypted_message = rsa.decrypt(encrypted_message, private_key)

    assert message == decrypted_message, (
        "Decrypted message does not match the original message."
    )
