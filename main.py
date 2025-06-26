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
from src.brute_force import brute_force_attack
from src.dictionary_attack import dictionary_attack

def attack_menu():
    print("""
Brute-force/Dictionary Attacks
------------------------------
1. Dictionary attack on stored user hash
2. Brute-force attack on stored user hash
3. Dictionary attack on custom hash
4. Brute-force attack on custom hash
0. Back to main menu
""")
    choice = input("Select an option: ")

    if choice == '1':
        username = input("Enter username to attack: ")
        if not username:
            print("Username cannot be blank.")
            input("Press Enter to continue...")
            return

        entry = get_hash(username)
        if not entry:
            print("No hash found for that username.")
            input("Press Enter to continue...")
            return

        print(f"Attacking {entry['algo']} hash for user '{username}'...")
        result = dictionary_attack(entry['hash'], entry.get('salt'), entry['algo'])
        if result:
            print(f"SUCCESS! Password is: {result}")
        else:
            print("FAILED! Password not found in dictionary.")
        input("Press Enter to continue...")

    elif choice == '2':
        username = input("Enter username to attack: ")
        if not username:
            print("Username cannot be blank.")
            input("Press Enter to continue...")
            return

        entry = get_hash(username)
        if not entry:
            print("No hash found for that username.")
            input("Press Enter to continue...")
            return

        try:
            max_length = int(input("Enter maximum password length to try (recommended: 3-4): "))
            if max_length < 1 or max_length > 6:
                print("Maximum length should be between 1 and 6 for reasonable time.")
                input("Press Enter to continue...")
                return
        except ValueError:
            print("Invalid length.")
            input("Press Enter to continue...")
            return

        print(f"Attacking {entry['algo']} hash for user '{username}'...")
        print(f"Warning: This may take a very long time for length > 4!")
        result = brute_force_attack(entry['hash'], entry.get('salt'), entry['algo'], max_length)
        if result:
            print(f"SUCCESS! Password is: {result}")
        else:
            print("FAILED! Password not found.")
        input("Press Enter to continue...")

    elif choice == '3':
        hash_input = input("Enter hash to attack: ")
        if not hash_input:
            print("Hash cannot be blank.")
            input("Press Enter to continue...")
            return

        algo = input("Enter algorithm (sha256/bcrypt): ").lower()
        if algo not in ['sha256', 'bcrypt']:
            print("Invalid algorithm. Use 'sha256' or 'bcrypt'.")
            input("Press Enter to continue...")
            return

        salt = None
        if algo == 'sha256':
            salt = input("Enter salt (hex): ")
            if not salt:
                print("Salt is required for SHA-256.")
                input("Press Enter to continue...")
                return

        result = dictionary_attack(hash_input, salt, algo)
        if result:
            print(f"SUCCESS! Password is: {result}")
        else:
            print("FAILED! Password not found in dictionary.")
        input("Press Enter to continue...")

    elif choice == '4':
        hash_input = input("Enter hash to attack: ")
        if not hash_input:
            print("Hash cannot be blank.")
            input("Press Enter to continue...")
            return

        algo = input("Enter algorithm (sha256/bcrypt): ").lower()
        if algo not in ['sha256', 'bcrypt']:
            print("Invalid algorithm. Use 'sha256' or 'bcrypt'.")
            input("Press Enter to continue...")
            return

        salt = None
        if algo == 'sha256':
            salt = input("Enter salt (hex): ")
            if not salt:
                print("Salt is required for SHA-256.")
                input("Press Enter to continue...")
                return

        try:
            max_length = int(input("Enter maximum password length to try (recommended: 3-4): "))
            if max_length < 1 or max_length > 6:
                print("Maximum length should be between 1 and 6 for reasonable time.")
                input("Press Enter to continue...")
                return
        except ValueError:
            print("Invalid length.")
            input("Press Enter to continue...")
            return

        print(f"Warning: This may take a very long time for length > 4!")
        result = brute_force_attack(hash_input, salt, algo, max_length)
        if result:
            print(f"SUCCESS! Password is: {result}")
        else:
            print("FAILED! Password not found.")
        input("Press Enter to continue...")

    elif choice == '0':
        return
    else:
        print("Invalid option.")
        input("Press Enter to continue...")

def password_hashing_menu():
    print("""
Password Hashing Utilities
-------------------------
1. Hash password with SHA-256 (PBKDF2) and store in DB
2. Hash password with bcrypt and store in DB
3. Verify password from DB (SHA-256 or bcrypt)
""")
    choice = input("Select an option: ")
    if choice == '1':
        username = input("Enter username: ")
        if not username:
            print("Username cannot be blank.")
            input("Press Enter to continue...")
            return
        pw = input("Enter password to hash: ")
        if not pw:
            print("Password cannot be blank.")
            input("Press Enter to continue...")
            return
        result = hash_password_sha256(pw)
        if store_hash(username, result['salt'], result['hash']):
            print(f"Hash and salt stored for user '{username}'.")
        else:
            print(f"Username '{username}' is already taken. Please choose another.")
        input("Press Enter to continue...")
    elif choice == '2':
        if not bcrypt_available:
            print("bcrypt is not installed. Run 'pip install bcrypt' to use this feature.")
            input("Press Enter to continue...")
            return
        username = input("Enter username: ")
        if not username:
            print("Username cannot be blank.")
            input("Press Enter to continue...")
            return
        pw = input("Enter password to hash (bcrypt): ")
        if not pw:
            print("Password cannot be blank.")
            input("Press Enter to continue...")
            return
        result = hash_password_bcrypt(pw)
        if store_hash(username, result['salt'], result['hash'], algo='bcrypt'):
            print(f"bcrypt hash and salt stored for user '{username}'.")
        else:
            print(f"Username '{username}' is already taken. Please choose another.")
        input("Press Enter to continue...")
    elif choice == '3':
        username = input("Enter username: ")
        if not username:
            print("Username cannot be blank.")
            input("Press Enter to continue...")
            return
        entry = get_hash(username)
        if not entry:
            print("No hash found for that username.")
            input("Press Enter to continue...")
            return
        pw = input("Enter password to verify: ")
        if not pw:
            print("Password cannot be blank.")
            input("Press Enter to continue...")
            return
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
2. Vigenère Cipher Encrypt
3. Vigenère Cipher Decrypt
0. Back to main menu
""")
    choice = input("Select an option: ")
    if choice == '1':
        msg = input("Enter message: ")
        if not msg:
            print("Message cannot be blank.")
            input("Press Enter to continue...")
            return
        try:
            shift = int(input("Enter shift: "))
        except ValueError:
            print("Shift must be an integer.")
            input("Press Enter to continue...")
            return
        enc = caesar_encrypt(msg, shift)
        print(f"Encrypted: {enc}")
        dec = caesar_decrypt(enc, shift)
        print(f"Decrypted: {dec}")
        input("Press Enter to continue...")
    elif choice == '2':
        msg = input("Enter message: ")
        if not msg:
            print("Message cannot be blank.")
            input("Press Enter to continue...")
            return
        key = input("Enter key: ")
        if not key:
            print("Key cannot be blank.")
            input("Press Enter to continue...")
            return
        enc = vigenere_encrypt(msg, key)
        print(f"Encrypted: {enc}")
        input("Press Enter to continue...")
    elif choice == '3':
        msg = input("Enter message: ")
        if not msg:
            print("Message cannot be blank.")
            input("Press Enter to continue...")
            return
        key = input("Enter key: ")
        if not key:
            print("Key cannot be blank.")
            input("Press Enter to continue...")
            return
        dec = vigenere_decrypt(msg, key)
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
        elif choice == '2':
            attack_menu()
        elif choice == '3':
            ciphers_menu()
        else:
            print("Feature coming soon! (This is a starter template.)")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
