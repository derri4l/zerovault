import argparse
import base64
import getpass
import json
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet

# file paths
SALT_FILE = "salt.bin"
VAULT_FILE = "vault.json"


# saltkey hashes our master password
def saltkey(password: str, salt: bytes) -> bytes:
    raw = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID,  # Argon2id
    )
    return base64.urlsafe_b64encode(raw)


# first time vault setup
def zsetup_vault():
    if os.path.exists(SALT_FILE) or os.path.exists(VAULT_FILE):
        print("Vault already exists. Delete salt.bin and vault.json to reset.")
        return

        # prompt for master password
    while True:
        password = getpass.getpass("Welcome to zerovault. Enter your master password: ")
        confirm = getpass.getpass("Confirm your master password")

        if password != confirm:
            print("Passwords don't match")
        else:
            print("Master password has been set successfully. Creating Vault...")
            break

    # write to salt.bin
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as g:
        g.write(salt)

    secret_key = saltkey(password, salt)
    fernet = Fernet(secret_key)
    token = fernet.encrypt(json.dumps({}).encode())

    with open(VAULT_FILE, "wb") as f:
        f.write(token)

    print("Vault created.")


def load_saltkey() -> bytes:
    with open(SALT_FILE, "rb") as ls:
        return ls.read()


# unlock_zvault derives the key from master password to decrypt the vault
def unlock_zvault(password: str) -> tuple[dict, Fernet]:
    salt = load_saltkey()
    secret_key = saltkey(password, salt)
    fernet = Fernet(secret_key)

    with open(VAULT_FILE, "rb") as v:
        token = v.read()
        data = json.loads(fernet.decrypt(token).decode())
    return data, fernet


# save_zvault saves any modified changes and encrypts the vault
def save_zvault(data: dict, fernet: Fernet):
    token = fernet.encrypt(json.dumps(data).encode())

    with open(VAULT_FILE, "wb") as sv:
        sv.write(token)


# zvault_add adds secrets to the vault by passing a label for it
def zvault_add(label: str):
    password = getpass.getpass("Enter your Master password: ")
    data, fernet = unlock_zvault(password)

    secret = getpass.getpass(f"Enter secret for '{label}': ")
    data[label] = secret
    save_zvault(data, fernet)
    print(f"'{label}' added.")


# zvault_get prints label: secret for a specific entry
def zvault_get(name: str):
    password = getpass.getpass("Enter your Master key ")
    data, _ = unlock_zvault(password)
    if name not in data:
        print(f"No entry for '{name}'.")
        return

    print(f"{name}: {data[name]}")


# zvault_list lists only the labels for all entries
def zvault_list():
    password = getpass.getpass("Enter your Master key: ")
    data, _ = unlock_zvault(password)

    if not data:
        print("Vault is empty.")
        return
    for key in data:
        print(f"  - {key}")
