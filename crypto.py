from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import yaml

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

ITERATIONS = config['crypto']['key_derivation']['iterations']
SALT_SIZE = config['crypto']['key_derivation']['salt_size']
AES_MODE = config['crypto']['aes']['mode']
KEY_SIZE = config['crypto']['aes']['key_size']

backend = default_backend()

# --------------------------
# Key Derivation
# --------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a symmetric key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=backend
    )
    return kdf.derive(password.encode())

# --------------------------
# Encryption
# --------------------------
def encrypt_file(file_path: str, password: str) -> bytes:
    """Encrypt a file using AES-GCM and append salt + nonce + tag for decryption"""
    # Read file content
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Generate salt and derive key
    salt = os.urandom(16)
    key = derive_key(password, salt)

    # Generate random nonce
    nonce = os.urandom(12)
    if AES_MODE == "GCM":
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
    elif AES_MODE == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=backend)
    else:
        raise ValueError("Unsupported AES mode : {AES_MODE}")
        
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    signature = generate_hmac(key, ciphertext)
    # Combine salt + nonce + tag + signature + ciphertext
    return salt + nonce + tag + signature + ciphertext

# --------------------------
# Decryption
# --------------------------
def decrypt_file(encrypted_bytes: bytes, password: str) -> bytes:
    """Decrypt AES-GCM encrypted file and verify integrity"""
    # Extract salt, nonce, tag
    salt = encrypted_bytes[:16]
    nonce = encrypted_bytes[16:28]
    tag = encrypted_bytes[28:44]
    signature = encrypted_bytes[44:76]
    ciphertext = encrypted_bytes[76:]

    # Derive key
    key = derive_key(password, salt)

    if not verify_hmac(key, ciphertext, signature):
        raise ValueError("Integrity check failed: HMAC does not match")
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# --------------------------
# HMAC (Optional extra integrity)
# --------------------------
def generate_hmac(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256(), backend=backend)
    h.update(data)
    return h.finalize()

def verify_hmac(key: bytes, data: bytes, signature: bytes) -> bool:
    h = hmac.HMAC(key, hashes.SHA256(), backend=backend)
    h.update(data)
    try:
        h.verify(signature)
        return True
    except Exception:
        return False
