import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derivate_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=500000)
    return kdf.derive(password.encode())

salt = os.urandom(16)
key = derivate_key("password", salt)
print(key.hex())