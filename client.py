from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import base64
import rsaTools as rsa
import requests

# --- CONFIG ---
GET_PUBLIC_KEY_URL = "http://localhost:8000/public-key"
POST_MESSAGE_URL = "http://localhost:8000/decrypt"
MESSAGE = b"Hello, RSA-secured server!"
# ---------------

# Step 1: Get the public key from server
response = requests.get(GET_PUBLIC_KEY_URL)
pem_str = response.json()["public_key"]

# Safe load
public_key = load_pem_public_key(pem_str.encode("utf-8"), backend=default_backend())
assert isinstance(public_key, RSAPublicKey), "Invalid public key type"
print("Public Key:", public_key)

# Step 3: Encrypt the message
cyphetext = rsa.encrypt(MESSAGE, public_key)

# Optional: Base64 encode it to send as string
encoded_msg = base64.b64encode(cyphetext).decode("utf-8")

# Step 4: Send it to the server
post_response = requests.post(POST_MESSAGE_URL, json={"encrypted_message": encoded_msg})

print("Server response:", post_response.text)
