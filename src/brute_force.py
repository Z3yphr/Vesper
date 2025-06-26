"""
brute_force.py - Brute-force attack module for Vesper

Provides functions for brute-force attacks on password hashes.
"""
import itertools
import string
from src.hash_utils import hash_password_sha256, verify_password_sha256
try:
    from src.bcrypt_utils import verify_password_bcrypt
    bcrypt_available = True
except ImportError:
    bcrypt_available = False

def brute_force_attack(target_hash: str, salt: str | None = None, algo: str = 'sha256', max_length: int = 4, charset: str | None = None):
    """
    Perform a brute-force attack on a hash.

    Args:
        target_hash: The hash to crack
        salt: Salt for the hash (required for SHA-256)
        algo: Algorithm used ('sha256' or 'bcrypt')
        max_length: Maximum password length to try
        charset: Character set to use (default: lowercase letters + digits)

    Returns:
        Cracked password or None if not found
    """
    if charset is None:
        charset = string.ascii_lowercase + string.digits

    print(f"Starting brute-force attack (max length: {max_length}, charset: {len(charset)} chars)")

    attempts = 0
    for length in range(1, max_length + 1):
        print(f"Trying passwords of length {length}...")
        for candidate in itertools.product(charset, repeat=length):
            password = ''.join(candidate)
            attempts += 1

            # Check if password matches
            if algo == 'sha256' and salt:
                if verify_password_sha256(password, salt, target_hash):
                    print(f"Password cracked in {attempts} attempts: {password}")
                    return password
            elif algo == 'bcrypt' and bcrypt_available:
                if verify_password_bcrypt(password, target_hash):
                    print(f"Password cracked in {attempts} attempts: {password}")
                    return password

            # Progress indicator
            if attempts % 1000 == 0:
                print(f"Tried {attempts} passwords...")

    print(f"Attack completed. Password not found after {attempts} attempts.")
    return None

if __name__ == "__main__":
    # Test with a simple password
    test_password = "abc"
    result = hash_password_sha256(test_password)
    print(f"Testing with password: {test_password}")
    cracked = brute_force_attack(result['hash'], result['salt'], 'sha256', 3)
    print(f"Result: {cracked}")
