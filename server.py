# server.py
from flask import Flask, request, jsonify
import base64, time
from cryptography.hazmat.primitives import serialization
import rsaTools as rsa

app = Flask(__name__)

private_key, public_key = rsa.generateRSAKeyPair()

print("Private Key:", private_key)
print("Public Key:", public_key)


def check_pkcs1_v15_padding(msg: bytes) -> bool:
    """
    Check PKCS1v15 padding
    Args:
        msg: the message to check.
    Returns:
       bool: true if everything if fine, else false.
    """
    # PKCS#1 v1.5: 0x00 | 0x02 | PS…| 0x00
    if len(msg) < 11 or msg[0:2] != b"\x00\x02":
        return False
    # find 0x00 separator after padding
    try:
        sep = msg.index(b"\x00", 2)
    except ValueError:
        return False
    return sep >= 10  # at least 8 bytes of PS


@app.route("/decrypt", methods=["POST"])
def decrypt():
    payload = request.get_json()
    ct_b64 = payload.get("ciphertext", "")
    try:
        ct = base64.b64decode(ct_b64)
    except Exception:
        return jsonify({"error": "bad base64"}), 400

    pt = rsa.decrypt(ct, private_key)
    valid = check_pkcs1_v15_padding(pt)

    # tiny artificial delay on invalid padding to leak timing
    if not valid:
        time.sleep(0.0001)

    if valid:
        return jsonify({"status": "ok"}), 200
    else:
        return jsonify({"status": "error"}), 500


@app.route("/public-key", methods=["GET"])
def get_public_key():
    # Convert public key to PEM format (bytes)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Convert bytes to string for JSON response
    return jsonify({"public_key": pem.decode("utf-8")})


if __name__ == "__main__":
    # debug off in prod
    app.run(host="0.0.0.0", port=8000)
