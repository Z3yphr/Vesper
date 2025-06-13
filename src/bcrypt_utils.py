"""
bcrypt_utils.py - Password hashing utilities using bcrypt for Vesper

Provides functions for hashing and verifying passwords using bcrypt.
Requires: pip install bcrypt
"""
import bcrypt

def hash_password_bcrypt(password: str) -> dict:
    """
    Hash a password using bcrypt.
    Returns a dict with salt and hash (both as utf-8 strings).
    """
    salt = bcrypt.gensalt()
    pwd_hash = bcrypt.hashpw(password.encode(), salt)
    return {
        'salt': salt.decode(),
        'hash': pwd_hash.decode()
    }

def verify_password_bcrypt(password: str, hash_str: str) -> bool:
    """
    Verify a password against a bcrypt hash.
    """
    return bcrypt.checkpw(password.encode(), hash_str.encode())

if __name__ == "__main__":
    pw = input("Enter password to hash (bcrypt): ")
    result = hash_password_bcrypt(pw)
    print(f"Salt: {result['salt']}")
    print(f"Hash: {result['hash']}")
    check = input("Re-enter password to verify: ")
    print("Verified:" if verify_password_bcrypt(check, result['hash']) else "Not verified.")
