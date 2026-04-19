import argparse
import base64
import getpass
import inspect
import json
import logging
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet


# logging
def zlogger():
    logging.basicConfig(
        filename=".zvault.log", level=logging.INFO, format="%(asctime)s - %(message)s"
    )


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
zlogger()
caller = inspect.stack()[0][3]


def unlock_zvault() -> tuple[dict, Fernet]:
    attempt = 0
    salt = load_saltkey()

    while attempt < 2:
        password = getpass.getpass("Enter your master password: ")
        secret_key = saltkey(password, salt)
        fernet = Fernet(secret_key)
        try:
            with open(VAULT_FILE, "rb") as v:
                token = v.read()
                data = json.loads(fernet.decrypt(token).decode())
            logging.info(f"{caller} → Success:unlocked")
            return data, fernet
            logging.info()
        except:
            attempt += 1
            logging.info(f"{caller} → Failed:unlock attempt {attempt}")
            print("Wrong password. Try again")
    logging.info(f"{caller} → max attempts reached")
    print("Wrong password. Exiting.")
    exit()


# save_zvault saves any modified changes and encrypts the vault
def save_zvault(data: dict, fernet: Fernet):
    token = fernet.encrypt(json.dumps(data).encode())

    with open(VAULT_FILE, "wb") as sv:
        sv.write(token)


# zvault_add adds secrets to the vault by passing a label for it
def zvault_add(label: str):
    data, fernet = unlock_zvault()

    if label in data:
        print("This label already exists")
        overwrite = input("Overwrite? (y/n): ")
        if overwrite == "n":
            exit()
        else:
            secret = getpass.getpass(f"Enter secret for '{label}': ")
            data[label] = secret
    else:
        secret = getpass.getpass(f"Enter secret for '{label}': ")
        data[label] = secret

    save_zvault(data, fernet)
    print(f"'{label}' added.")


# zvault_get prints 'label: secret' for a specific entry
def zvault_get(label: str):
    data, _ = unlock_zvault()
    if label not in data:
        print(f"No entry for '{label}'.")
        return

    print(f" {label} →  {data[label]}")


# zvault_list lists only the labels for all entries
def zvault_list():
    data, _ = unlock_zvault()

    if not data:
        print("Vault is empty.")
        return
    for key in data:
        print(f"→ {key}")
