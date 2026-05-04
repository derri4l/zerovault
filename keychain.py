import argparse
import base64
import getpass
import inspect
import json
import logging
import os

import pyperclip
from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken


# logging
def zlogger():
    logging.basicConfig(
        filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s"
    )


# variables
SALT_FILE = "salt.bin"
VAULT_FILE = "vault.json"
LOG_FILE = ".zvault.log"
TIME_COST = 2
MEMORY_COST = 65536
PARALLELISM = 2
HASH_LEN = 32
TYPE = Type.ID


# saltkey hashes our master password
def saltkey(password: str, salt: bytes) -> bytes:
    raw = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=TIME_COST,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len=HASH_LEN,
        type=TYPE,
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

    # generate salt.bin and write it into the vault
    salt = os.urandom(16)
    secret_key = saltkey(password, salt)
    fernet = Fernet(secret_key)
    token = fernet.encrypt(json.dumps({}).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(salt + token)
    os.chmod(VAULT_FILE, 0o600)
    print("Vault created.")


# confirmation model
def confirm_choice(max_attempts=3):
    attempt = 0
    while attempt < max_attempts:
        choice = input("[y]Yes or [n]No: ").strip().lower()
        if choice in ("y", "n"):
            return choice
        attempt += 1
        print("Invalid choice, please select [y]Yes or [no]")
    print("Too many invalid choices. Exiting")
    exit()


# setup logging for unlock_zvault
zlogger()
caller = inspect.stack()[0][
    3
]  # inspect module that called unlock_vault and logging info
if os.path.exists(LOG_FILE):
    os.chmod(LOG_FILE, 0o600)


# unlock_zvault derives the key from master password to decrypt the vault
def unlock_zvault() -> tuple[dict, Fernet, bytes]:
    attempt = 0
    while attempt < 2:
        password = getpass.getpass("Enter your master password: ")
        with open(VAULT_FILE, "rb") as v:
            data = v.read()
        salt, token = data[:16], data[16:]
        secret_key = saltkey(password, salt)
        fernet = Fernet(secret_key)
        try:
            entry = json.loads(fernet.decrypt(token).decode())
            logging.info(f"{caller} → Success:unlocked")
            return entry, fernet, salt
            # exit after 3 invalid attempts
        except InvalidToken:
            attempt += 1
            logging.info(f"{caller} → Failed:unlock attempt {attempt}")
            print("Wrong password. Try again")
    logging.info(f"{caller} → max attempts reached")
    print("Wrong password. Exiting.")
    exit()


# save_zvault saves any modified changes and encrypts the vault
def save_zvault(entry: dict, fernet: Fernet, salt: bytes):
    token = fernet.encrypt(json.dumps(entry).encode())
    with open(VAULT_FILE, "wb") as sv:
        sv.write(salt + token)


# zvault_add adds secrets to the vault by passing a label for it
def zvault_add(label: str):
    entry, fernet, salt = unlock_zvault()

    if label in entry:
        print("This label already exists")
        overwrite = input("Overwrite? (y/n): ")
        if overwrite == "n":
            exit()
        else:
            secret = getpass.getpass(f"Enter secret for '{label}': ")
            entry[label] = secret
    else:
        secret = getpass.getpass(f"Enter secret for '{label}': ")
        entry[label] = secret

    save_zvault(entry, fernet, salt)
    print(f"'{label}' added.")


# zvault_del
def zvault_del(label: str):
    entry, fernet, salt = unlock_zvault()

    if label not in entry:
        print(f"'{label}' does not exist")
        return

    print(f"Are you sure you want to delete {label}")
    confirm = confirm_choice()
    if confirm == "n":
        print("Aborted")
        return

    else:
        del entry[label]

    logging.info(f"{caller} → {label} was deleted")
    save_zvault(entry, fernet, salt)
    print(f"'{label}' has been deleted.")


# zvault_get prints 'label: secret' for a specific entry
def zvault_get(label: str):
    entry, _, _ = unlock_zvault()
    if label not in entry:
        print(f"No entry for '{label}'.")
        return

        # copy the secret to clipboard instead
    pyperclip.copy(entry[label])
    print(f"'{label}' has been copied to the clipboard!")


# zvault_list lists only the labels for all entries
def zvault_list():
    entry, _, _ = unlock_zvault()

    if not entry:
        print("Vault is empty.")
        return
    for key in entry:
        print(f"- '{key}'")
