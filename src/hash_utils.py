"""
hash_utils.py - Password hashing utilities for Vesper

Provides functions for hashing and verifying passwords using secure algorithms.
"""
import hashlib
import os
import binascii

def hash_password_sha256(password: str, salt: bytes = None) -> dict:
    """
    Hash a password using SHA-256 with a random salt.
    Returns a dict with salt and hash (both hex-encoded).
    """
    if salt is None:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return {
        'salt': binascii.hexlify(salt).decode(),
        'hash': binascii.hexlify(pwd_hash).decode()
    }

def verify_password_sha256(password: str, salt_hex: str, hash_hex: str) -> bool:
    """
    Verify a password against a given salt and hash (hex-encoded).
    """
    salt = binascii.unhexlify(salt_hex)
    expected_hash = binascii.unhexlify(hash_hex)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return pwd_hash == expected_hash

if __name__ == "__main__":
    pw = input("Enter password to hash: ")
    result = hash_password_sha256(pw)
    print(f"Salt: {result['salt']}")
    print(f"Hash: {result['hash']}")
    check = input("Re-enter password to verify: ")
    print("Verified:" if verify_password_sha256(check, result['salt'], result['hash']) else "Not verified.")
