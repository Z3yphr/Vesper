"""
dictionary_attack.py - Dictionary attack module for Vesper

Provides functions for dictionary-based attacks on password hashes.
"""
import sys
import time
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
    "test", "guest", "hello", "world", "secret", "changeme", "abc", "123"
]

def show_progress_bar(current: int, total: int, width: int = 50) -> str:
    """Generate a progress bar string."""
    progress = current / total
    filled = int(width * progress)
    bar = '█' * filled + '░' * (width - filled)
    percentage = progress * 100
    return f"[{bar}] {percentage:.1f}% ({current}/{total})"

def show_spinner(attempts: int, password: str) -> None:
    """Show a spinning animation with current password being tested."""
    spinner_chars = ['|', '/', '-', '\\']
    spinner = spinner_chars[attempts % 4]
    # Truncate password if too long for display
    display_pwd = password[:20] + "..." if len(password) > 20 else password
    sys.stdout.write(f"\r{spinner} Testing: {display_pwd}")
    sys.stdout.flush()

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
    print("Progress:")

    start_time = time.time()

    for i, password in enumerate(wordlist):
        # Show progress
        if len(wordlist) > 10:
            progress_bar = show_progress_bar(i + 1, len(wordlist))
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"\r{progress_bar} | {rate:.1f} passwords/sec", end="")
        else:
            show_spinner(i, password)

        # Check if password matches
        if algo == 'sha256' and salt:
            if verify_password_sha256(password, salt, target_hash):
                elapsed = time.time() - start_time
                print(f"\n✓ PASSWORD CRACKED: {password} (found in {elapsed:.2f}s)")
                return password
        elif algo == 'bcrypt' and bcrypt_available:
            if verify_password_bcrypt(password, target_hash):
                elapsed = time.time() - start_time
                print(f"\n✓ PASSWORD CRACKED: {password} (found in {elapsed:.2f}s)")
                return password

    elapsed = time.time() - start_time
    print(f"\n\n❌ Dictionary attack completed. Password not found after trying {len(wordlist)} passwords ({elapsed:.2f}s)")
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
