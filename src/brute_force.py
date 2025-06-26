"""
brute_force.py - Comprehensive brute-force attack module for Vesper

Provides single-threaded brute-force attacks with advanced progress tracking.
"""
import itertools
import string
import sys
import time
from src.hash_utils import hash_password_sha256, verify_password_sha256
from src.progress_indicators import ThreadSafeProgressTracker, ProgressMonitor, SimpleSpinner
try:
    from src.bcrypt_utils import verify_password_bcrypt
    bcrypt_available = True
except ImportError:
    bcrypt_available = False
    verify_password_bcrypt = None


def brute_force_attack(target_hash: str, salt: str | None = None, algo: str = 'sha256',
                      max_length: int = 4, charset: str | None = None):
    """
    Single-threaded brute-force attack with progress indicators.

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

    print(f"🚀 Starting single-threaded brute-force attack")
    print(f"📏 Max length: {max_length} | 🔤 Charset: {len(charset)} chars")

    attempts = 0
    total_combinations = sum(len(charset) ** length for length in range(1, max_length + 1))

    print(f"🔢 Total combinations: {total_combinations:,}")

    # Use appropriate progress tracking
    progress_tracker = None
    progress_monitor = None
    spinner = None

    if total_combinations > 1000:
        progress_tracker = ThreadSafeProgressTracker(total_combinations, 1, update_interval=1.0)
        progress_monitor = ProgressMonitor(progress_tracker)
        progress_monitor.start()
        use_progress = True
    else:
        spinner = SimpleSpinner("Testing passwords")
        use_progress = False

    start_time = time.time()

    try:
        for length in range(1, max_length + 1):
            length_combinations = len(charset) ** length
            print(f"\n🔍 Trying passwords of length {length} ({length_combinations:,} combinations)")

            for i, candidate in enumerate(itertools.product(charset, repeat=length)):
                password = ''.join(candidate)
                attempts += 1

                # Check if password matches
                if algo == 'sha256' and salt:
                    if verify_password_sha256(password, salt, target_hash):
                        elapsed = time.time() - start_time
                        print(f"\n✅ PASSWORD CRACKED: '{password}'")
                        print(f"⏱️  Time: {elapsed:.2f} seconds")
                        print(f"🔢 Attempts: {attempts:,}")
                        return password
                elif algo == 'bcrypt' and bcrypt_available and verify_password_bcrypt is not None:
                    if verify_password_bcrypt(password, target_hash):
                        elapsed = time.time() - start_time
                        print(f"\n✅ PASSWORD CRACKED: '{password}'")
                        print(f"⏱️  Time: {elapsed:.2f} seconds")
                        print(f"🔢 Attempts: {attempts:,}")
                        return password

                # Update progress
                if use_progress and progress_tracker:
                    if attempts % 100 == 0:  # Update every 100 attempts
                        progress_tracker.update(100)
                elif not use_progress and spinner:
                    if attempts % 50 == 0:  # Update spinner every 50 attempts
                        spinner.tick()

    except KeyboardInterrupt:
        print("\n⚠️  Attack interrupted by user.")
        return None
    finally:
        if use_progress and progress_monitor:
            progress_monitor.stop()
        elif not use_progress and spinner:
            spinner.finish("Attack completed")

    elapsed = time.time() - start_time
    print(f"\n❌ Attack completed without success")
    print(f"⏱️  Time: {elapsed:.2f} seconds")
    print(f"🔢 Total attempts: {attempts:,}")
    return None
