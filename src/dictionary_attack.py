"""
dictionary_attack.py - Dictionary attack module for Vesper

Provides functions for dictionary-based attacks on password hashes.
"""
from src.hash_utils import hash_password_sha256, verify_password_sha256
try:
    from src.bcrypt_utils import verify_password_bcrypt
    bcrypt_available = True
except ImportError:
    bcrypt_available = False

# Common passwords for dictionary attack
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "qwerty", "letmein",
    "welcome", "monkey", "1234567890", "abc123", "Password1", "password1",
    "123456789", "welcome123", "admin123", "root", "toor", "pass",
    "test", "guest", "hello", "world", "secret", "changeme"
]

def dictionary_attack(target_hash: str, salt: str | None = None, algo: str = 'sha256', wordlist: list[str] | None = None):
    """
    Perform a dictionary attack on a hash.

    Args:
        target_hash: The hash to crack
        salt: Salt for the hash (required for SHA-256)
        algo: Algorithm used ('sha256' or 'bcrypt')
        wordlist: List of passwords to try (default: common passwords)

    Returns:
        Cracked password or None if not found
    """
    if wordlist is None:
        wordlist = COMMON_PASSWORDS

    print(f"Starting dictionary attack with {len(wordlist)} passwords...")

    for i, password in enumerate(wordlist):
        # Check if password matches
        if algo == 'sha256' and salt:
            if verify_password_sha256(password, salt, target_hash):
                print(f"Password cracked: {password}")
                return password
        elif algo == 'bcrypt' and bcrypt_available:
            if verify_password_bcrypt(password, target_hash):
                print(f"Password cracked: {password}")
                return password

        # Progress indicator
        if (i + 1) % 5 == 0:
            print(f"Tried {i + 1}/{len(wordlist)} passwords...")

    print("Dictionary attack completed. Password not found.")
    return None

def load_wordlist_from_file(filename: str) -> list:
    """Load a wordlist from a file."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return []

if __name__ == "__main__":
    # Test with a common password
    test_password = "password123"
    result = hash_password_sha256(test_password)
    print(f"Testing with password: {test_password}")
    cracked = dictionary_attack(result['hash'], result['salt'], 'sha256')
    print(f"Result: {cracked}")
