import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import base64
import getpass
import argparse
from cryptography.exceptions import InvalidTag


FILE = "manager.json"
ITERATIONS = 500000

class PasswordManager:
    def __init__(self, master_password):
        self.master_pwd = master_password
        self.sel = None
        self.entries_pwd = {}

    def _derivate_key(self, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
        return kdf.derive(self.master_pwd.encode())

    def load(self):
        if not os.path.exists(FILE):
            self.sel = os.urandom(16)
            self.entries_pwd = {}
            return True

        with open(FILE, 'r') as f:
            data = json.load(f)

        self.sel = base64.b64decode(data["sel"])
        key = self._derivate_key(self.sel)
        data = base64.b64decode(data["data"])

        try:
            aesgcm = AESGCM(key)
            nonce = data[:12]
            cipher = data[12:]
            decrypted_data = aesgcm.decrypt(nonce, cipher, None)
            self.entries_pwd = json.loads(decrypted_data.decode())
            return True
        except InvalidTag:
            print("Master password is incorrect")
            return False

    def save(self):
        key = self._derivate_key(self.sel)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_data = json.dumps(self.entries_pwd).encode()
        cipher = nonce + aesgcm.encrypt(nonce, encrypted_data, None)
        data = {"sel": base64.b64encode(self.sel).decode(), "data": base64.b64encode(cipher).decode()}

        with open(FILE, 'w') as f:
            json.dump(data, f, indent=2)

    def add(self, webbsite, pwd):
        self.entries_pwd[webbsite] = pwd
        self.save()
        print(f"Password added for website : {webbsite}")

    def read(self, website):
        if website in self.entries_pwd:
            print(f"{website} : {self.entries_pwd[website]}")
        else:
            print(f"No entry for website : {website}")

    def list(self):
        if not self.entries_pwd:
            print("No entries")
        else:
            for website in sorted(self.entries_pwd.keys()):
                print(f" - {website}")

    def delete(self, website):
        if website in self.entries_pwd:
            del self.entries_pwd[website]
            self.save()
            print(f"Password removed for website : {website}")
        else:
            print(f"No entry for website : {website}")


def main():
    parser = argparse.ArgumentParser(description="Encrypted password manager")
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Add a new password")
    p_add.add_argument("website")

    p_get = sub.add_parser("get", help="Get password")
    p_get.add_argument("website")

    sub.add_parser("list", help="List all websites")

    p_del = sub.add_parser("delete", help="Delete password")
    p_del.add_argument("website")

    args = parser.parse_args()

    master = getpass.getpass(prompt="Master password: ")
    pwd_manager = PasswordManager(master)
    if not pwd_manager.load():
        return

    if args.command == "add":
        pwd = getpass.getpass(prompt= f"Password for {args.website}: ")
        pwd_manager.add(args.website, pwd)
    elif args.command == "get":
        pwd_manager.read(args.website)
    elif args.command == "list":
        pwd_manager.list()
    elif args.command == "delete":
        pwd_manager.delete(args.website)




if __name__ == "__main__":
    main()