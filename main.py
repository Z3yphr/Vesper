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
from src.caesar_cipher import caesar_encrypt, caesar_decrypt
from src.vigenere_cipher import vigenere_encrypt, vigenere_decrypt

def password_hashing_menu():
    print("""
Password Hashing Utilities
-------------------------
1. Hash password with SHA-256 (PBKDF2) and store in DB
2. Verify password from DB (SHA-256 or bcrypt)
3. Hash password with bcrypt and store in DB
0. Back to main menu
""")
    choice = input("Select an option: ")
    if choice == '1':
        username = input("Enter username: ")
        pw = input("Enter password to hash: ")
        result = hash_password_sha256(pw)
        if store_hash(username, result['salt'], result['hash']):
            print(f"Hash and salt stored for user '{username}'.")
        else:
            print(f"Username '{username}' is already taken. Please choose another.")
        input("Press Enter to continue...")
    elif choice == '2':
        username = input("Enter username: ")
        entry = get_hash(username)
        if not entry:
            print("No hash found for that username.")
            input("Press Enter to continue...")
            return
        pw = input("Enter password to verify: ")
        if entry['algo'] == 'sha256':
            verified = verify_password_sha256(pw, entry['salt'], entry['hash'])
        elif entry['algo'] == 'bcrypt' and bcrypt_available:
            verified = verify_password_bcrypt(pw, entry['hash'])
        elif entry['algo'] == 'bcrypt' and not bcrypt_available:
            print("bcrypt is not installed. Cannot verify this password.")
            input("Press Enter to continue...")
            return
        else:
            print(f"Unknown algorithm: {entry['algo']}")
            input("Press Enter to continue...")
            return
        print("Verified!" if verified else "Not verified.")
        input("Press Enter to continue...")
    elif choice == '3':
        if not bcrypt_available:
            print("bcrypt is not installed. Run 'pip install bcrypt' to use this feature.")
            input("Press Enter to continue...")
            return
        username = input("Enter username: ")
        pw = input("Enter password to hash (bcrypt): ")
        result = hash_password_bcrypt(pw)
        if store_hash(username, result['salt'], result['hash'], algo='bcrypt'):
            print(f"bcrypt hash and salt stored for user '{username}'.")
        else:
            print(f"Username '{username}' is already taken. Please choose another.")
        input("Press Enter to continue...")
    elif choice == '0':
        return
    else:
        print("Invalid option.")
        input("Press Enter to continue...")

def ciphers_menu():
    print("""
Classic Ciphers
---------------
1. Caesar Cipher (Encrypt/Decrypt)
2. Vigenère Cipher (Encrypt/Decrypt)
0. Back to main menu
""")
    choice = input("Select an option: ")
    if choice == '1':
        msg = input("Enter message: ")
        shift = int(input("Enter shift: "))
        enc = caesar_encrypt(msg, shift)
        print(f"Encrypted: {enc}")
        dec = caesar_decrypt(enc, shift)
        print(f"Decrypted: {dec}")
        input("Press Enter to continue...")
    elif choice == '2':
        msg = input("Enter message: ")
        key = input("Enter key: ")
        enc = vigenere_encrypt(msg, key)
        print(f"Encrypted: {enc}")
        dec = vigenere_decrypt(enc, key)
        print(f"Decrypted: {dec}")
        input("Press Enter to continue...")
    elif choice == '0':
        return
    else:
        print("Invalid option.")
        input("Press Enter to continue...")

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
        elif choice == '3':
            ciphers_menu()
        else:
            print("Feature coming soon! (This is a starter template.)")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
