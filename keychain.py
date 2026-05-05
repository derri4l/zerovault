import argparse
import base64
import getpass
import inspect
import json
import logging
import os
import string

import pyperclip
from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken

# variables/parameters
SALT_FILE = "salt.bin"
VAULT_FILE = "vault.json"
LOG_FILE = ".zvault.log"
TIME_COST = 4
MEMORY_COST = 262144
PARALLELISM = 2
HASH_LEN = 32
TYPE = Type.ID



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


# check for master password strength with feedback
def master_strength(masterp: str) -> bool:
    if len(masterp) < 8:
        print("Password too short, minimum 8 characters.")
        return False
    if not any(c.isupper() for c in masterp):
        print("Password must contain an UPPERCASE letter.")
        return False
    if not any(c.islower() for c in masterp):
        print("Password must contain a lowercase letter.")
        return False
    if not any(c.isdigit() for c in masterp):
        print("Password must contain a number.")
        return False
    if not any(c in string.punctuation for c in masterp):
        print("Password must contain a special character.")
        return False
    return True


# zvault_init initializes the vault for the first time
def zvault_init():
    if os.path.exists(VAULT_FILE):
        print("Vault already exists. Delete vault.json to reset the vault.")
        return

    # prompt for first setup master password
    attempt = 0
    while attempt < 3:
        password = getpass.getpass("First time? Enter your master password: ")
        # check for password strength
        if not master_strength(password):
            attempt += 1
            continue
        confirm = getpass.getpass("Confirm your master password: ")
        if password != confirm:
            print("Passwords don't match")
            attempt += 1
            continue
        print("Master password set. Creating Vault...")
        break
    else:
        print("Too many failed attempts. Exiting.")
        exit()

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


# unlock_zvault derives the key from master password to decrypt the vault
def unlock_zvault() -> tuple[dict, Fernet, bytes]:
    attempt = 0
    while attempt < 3:
        password = getpass.getpass("Enter your master password: ")
        with open(VAULT_FILE, "rb") as v:
            data = v.read()
        salt, token = data[:16], data[16:]
        secret_key = saltkey(password, salt)
        fernet = Fernet(secret_key)
        try:
            entry = json.loads(fernet.decrypt(token).decode())

            return entry, fernet, salt
            # exit after 3 invalid attempts
        except InvalidToken:
            attempt += 1
            print("Wrong password. Try again")
    print("Wrong password. Exiting.")
    exit()


# save_zvault saves any modified changes and re-encrypts the vault
def save_zvault(entry: dict, fernet: Fernet, salt: bytes):
    token = fernet.encrypt(json.dumps(entry).encode())
    with open(VAULT_FILE, "wb") as sv:
        sv.write(salt + token)


# zvault_add adds secrets to the vault by passing a label for it. eg. 'zvault add github'
def zvault_add(label: str):
    entry, fernet, salt = unlock_zvault()
    # check if entry already exists
    if label in entry:
        print("This label already exists, Overwrite?")
        choice = confirm_choice()
        if choice == "n":
            print("Aborted")
            return
        else:
            # secret would be the actual password you for the label passed
            secret = getpass.getpass(f"Enter secret for '{label}': ")
            entry[label] = secret
    else:
        secret = getpass.getpass(f"Enter secret for '{label}': ")
        entry[label] = secret

    save_zvault(entry, fernet, salt)
    print(f"'{label}' added.")


# zvault_del deletes the entire entry by also passing the label for it. eg. 'zvault del github'
def zvault_del(label: str):
    entry, fernet, salt = unlock_zvault()
# check if the label exists
    if label not in entry:
        print(f"'{label}' does not exist")
        return
# confirm user wants to delete the entry
    print(f"Are you sure you want to delete {label}")
    confirm = confirm_choice()
    if confirm == "n":
        print("Aborted")
        return
    else:
        del entry[label]
        
    save_zvault(entry, fernet, salt)
    print(f"'{label}' has been deleted.")


# zvault_get copies the password/secret directly into your clipboard. eg. 'zvault get github'
def zvault_get(label: str):
    entry, _, _ = unlock_zvault()
    if label not in entry:
        print(f"No entry for '{label}'.")
        return
        
        # copy the secret to clipboard instead
    pyperclip.copy(entry[label])
    print(f"'{label}' has been copied to the clipboard!")


# zvault_list lists the available labels in the vault. eg. 'zvault list'
def zvault_list():
    entry, _, _ = unlock_zvault()

    if not entry:
        print("Vault is empty.")
        return
        
    for key in entry:
        print(f"- {key}")
