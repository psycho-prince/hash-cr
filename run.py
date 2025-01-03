#!/usr/bin/python

import io
import getopt
import hashlib
import sys
import os
import time
from cryptography.fernet import Fernet

# ASCII Art Header
def ascii_art():
    print("""
  _   _           _    _    ____                 
 | | | | __ _ ___| | _| | _|  _ \ ___  __ _ _ __ 
 | |_| |/ _` / __| |/ / |/ / |_) / _ \/ _` | '__|
 |  _  | (_| \__ \   <|   <|  __/  __/ (_| | |   
 |_| |_|\__,_|___/_|\_\_|\_\_|   \___|\__,_|_|   
                 Hash Cracky v4.1
    """)

# Generate and write an encryption key
def write_encryption_key():
    key = Fernet.generate_key()
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)

# Load the encryption key
def load_encryption_key():
    return open("encryption_key.key", "rb").read()

# Encrypt data with Fernet
def encrypt_data(data):
    key = load_encryption_key()
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Decrypt data with Fernet
def decrypt_data(data):
    key = load_encryption_key()
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

# Display system information
def check_os():
    if os.name == "nt":
        return "Windows"
    elif os.name == "posix":
        return "Linux/Unix"
    else:
        return "Unknown OS"

# Display additional information
def info():
    print("\nInformation:")
    print("[*] Options:")
    print("[*] (-h) Hash")
    print("[*] (-t) Type [Supported: md5, sha1, sha224, sha256, sha384, sha512]")
    print("[*] (-w) Wordlist (Optional)")
    print("[*] (-n) Numbers brute force")
    print("[*] (-v) Verbose [{WARNING} Slows cracking down!]\n")
    print("[*] Examples:")
    print("[>] ./Hash-Cracker.py -h <hash> -t md5 -w DICT.txt")
    print("[>] ./Hash-Cracker.py -h <hash> -t sha256 -n -v")
    print("[*] If no wordlist is provided, a built-in wordlist is used.")

# Built-in wordlist (popular passwords)
BUILT_IN_WORDLIST = [
    "password", "123456", "123456789", "12345", "12345678",
    "qwerty", "1234567", "111111", "123123", "abc123",
    "letmein", "monkey", "iloveyou", "1234", "000000"
]

# Hash-cracking functionality
class HashCracking:

    def hash_crack_wordlist(self, user_hash, hash_type, wordlist, verbose, brute_force=False):
        start = time.time()
        solved = False
        self.line_count = 0

        # Select hash function
        try:
            hash_function = getattr(hashlib, hash_type)
        except AttributeError:
            print(f"[-] Unsupported hash type: {hash_type}")
            sys.exit()

        if brute_force:
            while True:
                line = str(self.line_count)
                number_hash = hash_function(line.encode()).hexdigest()
                if verbose:
                    sys.stdout.write(f"\rTrying: {line} " + " " * 20)
                    sys.stdout.flush()
                if number_hash == user_hash:
                    self._save_and_exit(line, number_hash, start)
                else:
                    self.line_count += 1
        else:
            # Use provided wordlist or built-in wordlist
            words = BUILT_IN_WORDLIST if wordlist is None else open(wordlist, "r").readlines()
            for line in words:
                line = line.strip()
                line_hash = hash_function(line.encode()).hexdigest()
                if verbose:
                    sys.stdout.write(f"\rTrying: {line} " + " " * 20)
                    sys.stdout.flush()

                if line_hash == user_hash:
                    self._save_and_exit(line, line_hash, start)
                else:
                    self.line_count += 1

        print("\n[-] Hash not found in wordlist.")
        print("[*] Try another wordlist or enable brute force.")

    def _save_and_exit(self, result, hashed_value, start_time):
        end = time.time()
        print(f"\n[+] Hash found: {result}")
        print(f"[+] Time taken: {round(end - start_time, 2)} seconds")

        # Encrypt and save the hash result
        encrypted_result = encrypt_data(f"{result}:{hashed_value}")
        with open("SavedHashes.txt", "ab") as f:
            f.write(encrypted_result + b"\n")
        print("[*] Hash saved to SavedHashes.txt (encrypted).")
        sys.exit()

# Main function
def main(argv):
    ascii_art()
    print(f"[Running on {check_os()}]\n")

    hash_type = None
    user_hash = None
    wordlist = None
    verbose = False
    numbers_brute_force = False

    # Parse command-line arguments
    try:
        opts, _ = getopt.getopt(argv, "ih:t:w:nv")
    except getopt.GetoptError:
        print("[*] Invalid usage. Use -i for help.")
        sys.exit()

    for opt, arg in opts:
        if opt == "-i":
            info()
            sys.exit()
        elif opt == "-t":
            hash_type = arg.strip().lower()
        elif opt == "-h":
            user_hash = arg.strip().lower()
        elif opt == "-w":
            wordlist = arg
        elif opt == "-v":
            verbose = True
        elif opt == "-n":
            numbers_brute_force = True

    if not hash_type or not user_hash:
        print("[*] Missing required arguments. Use -i for help.")
        sys.exit()

    # Load encryption key
    if not os.path.exists("encryption_key.key"):
        write_encryption_key()

    print(f"[*] Hash: {user_hash}")
    print(f"[*] Hash Type: {hash_type}")
    print(f"[*] Wordlist: {'Built-in' if wordlist is None else wordlist}")
    print("[+] Starting hash cracking...\n")

    # Start cracking
    cracker = HashCracking()
    cracker.hash_crack_wordlist(user_hash, hash_type, wordlist, verbose, brute_force=numbers_brute_force)

if __name__ == "__main__":
    main(sys.argv[1:])

