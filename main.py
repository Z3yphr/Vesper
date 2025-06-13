"""
main.py - Entry point for the Vesper Cybersecurity & Cryptography Practice Suite

This script will serve as the main menu for accessing password cracking, hashing, and cipher modules.
"""

import sys

def main():
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
    else:
        print("Feature coming soon! (This is a starter template.)")

if __name__ == "__main__":
    main()
