import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derivate_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=500000)
    return kdf.derive(password.encode())

salt = os.urandom(16)
key = derivate_key("password", salt)
print(key.hex())

def cipher(key, text):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    cipher = aesgcm.encrypt(nonce, text.encode(), None)
    return nonce + cipher

def decipher(key, data):
    aesgcm = AESGCM(key)
    nonce = data[:12]
    cipher = data[12:]
    decrypted_data = aesgcm.decrypt(nonce, cipher, None)
    return decrypted_data.decode()

enc = cipher(key, "hello password")
print(enc.hex())
dec = decipher(key, enc)
print(dec)