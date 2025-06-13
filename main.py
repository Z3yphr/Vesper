"""
main.py - Entry point for the Vesper Cybersecurity & Cryptography Practice Suite

This script will serve as the main menu for accessing password cracking, hashing, and cipher modules.
"""

import sys
from src.hash_utils import hash_password_sha256, verify_password_sha256
try:
    from src.bcrypt_utils import hash_password_bcrypt, verify_password_bcrypt
    bcrypt_available = True
except ImportError:
    bcrypt_available = False
from src.hash_db import init_db, store_hash, get_hash

def password_hashing_menu():
    print("""
Password Hashing Utilities
-------------------------
1. Hash password with SHA-256 (PBKDF2) and store in DB
2. Verify password with SHA-256 (PBKDF2) from DB
3. Hash password with bcrypt
0. Back to main menu
""")
    choice = input("Select an option: ")
    if choice == '1':
        username = input("Enter username: ")
        pw = input("Enter password to hash: ")
        result = hash_password_sha256(pw)
        store_hash(username, result['salt'], result['hash'])
        print(f"Hash and salt stored for user '{username}'.")
    elif choice == '2':
        username = input("Enter username: ")
        entry = get_hash(username)
        if not entry:
            print("No hash found for that username.")
            return
        pw = input("Enter password to verify: ")
        if verify_password_sha256(pw, entry['salt'], entry['hash']):
            print("Verified!")
        else:
            print("Not verified.")
    elif choice == '3':
        if not bcrypt_available:
            print("bcrypt is not installed. Run 'pip install bcrypt' to use this feature.")
            return
        pw = input("Enter password to hash (bcrypt): ")
        result = hash_password_bcrypt(pw)
        print(f"Salt: {result['salt']}")
        print(f"Hash: {result['hash']}")
        check = input("Re-enter password to verify: ")
        print("Verified!" if verify_password_bcrypt(check, result['hash']) else "Not verified.")
    elif choice == '0':
        return
    else:
        print("Invalid option.")

def main():
    init_db()
    while True:
        print("""
Vesper: Cybersecurity & Cryptography Practice Suite
---------------------------------------------------
1. Password Hashing Utilities
2. Brute-force/Dictionary Attacks
3. Classic Ciphers
4. Hash/Crack Utilities
0. Exit
""")
        choice = input("Select an option: ")
        if choice == '0':
            print("Exiting. Goodbye!")
            sys.exit(0)
        elif choice == '1':
            password_hashing_menu()
        else:
            print("Feature coming soon! (This is a starter template.)")

if __name__ == "__main__":
    main()
