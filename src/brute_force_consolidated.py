"""
brute_force.py - Comprehensive brute-force attack module for Vesper

Provides single-threaded and multithreaded brute-force attacks with advanced progress tracking.
"""
import itertools
import string
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.hash_utils import hash_password_sha256, verify_password_sha256
from src.progress_indicators import ThreadSafeProgressTracker, ProgressMonitor, SimpleSpinner
try:
    from src.bcrypt_utils import verify_password_bcrypt
    bcrypt_available = True
except ImportError:
    bcrypt_available = False


class BruteForceWorker:
    """Worker class for multithreaded brute-force attacks."""

    def __init__(self, target_hash: str, salt: str | None, algo: str):
        self.target_hash = target_hash
        self.salt = salt
        self.algo = algo
        self.found = False
        self.result = None
        self.lock = threading.Lock()

    def test_password_batch(self, password_batch: list[str]) -> tuple[str | None, int]:
        """Test a batch of passwords. Returns the cracked password (or None) and attempt count."""
        local_attempts = 0
        for password in password_batch:
            if self.found:  # Another thread found it
                return None, local_attempts

            local_attempts += 1

            # Test password
            if self.algo == 'sha256' and self.salt:
                if verify_password_sha256(password, self.salt, self.target_hash):
                    with self.lock:
                        if not self.found:
                            self.found = True
                            self.result = password
                    return password, local_attempts
            elif self.algo == 'bcrypt' and bcrypt_available:
                if verify_password_bcrypt(password, self.target_hash):
                    with self.lock:
                        if not self.found:
                            self.found = True
                            self.result = password
                    return password, local_attempts

        return None, local_attempts


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
                elif algo == 'bcrypt' and bcrypt_available:
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


def brute_force_attack_threaded(target_hash: str, salt: str | None = None, algo: str = 'sha256',
                               max_length: int = 4, charset: str | None = None, num_threads: int = 4):
    """
    Basic multithreaded brute-force attack.

    Args:
        target_hash: The hash to crack
        salt: Salt for the hash (required for SHA-256)
        algo: Algorithm used ('sha256' or 'bcrypt')
        max_length: Maximum password length to try
        charset: Character set to use (default: lowercase letters + digits)
        num_threads: Number of threads to use

    Returns:
        Cracked password or None if not found
    """
    if charset is None:
        charset = string.ascii_lowercase + string.digits

    print(f"🚀 Starting basic multithreaded brute-force attack ({num_threads} threads)")
    print(f"📏 Max length: {max_length} | 🔤 Charset: {len(charset)} chars")

    worker = BruteForceWorker(target_hash, salt, algo)
    total_combinations = sum(len(charset) ** length for length in range(1, max_length + 1))
    print(f"🔢 Total combinations: {total_combinations:,}")

    # Initialize progress tracking
    progress_tracker = ThreadSafeProgressTracker(total_combinations, num_threads, update_interval=0.5)
    progress_monitor = ProgressMonitor(progress_tracker, stop_condition=lambda: worker.found)

    start_time = time.time()
    batch_size = max(100, total_combinations // (num_threads * 10))  # Larger batches for basic version

    try:
        # Start progress monitoring
        progress_monitor.start()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []

            for length in range(1, max_length + 1):
                if worker.found:
                    break

                print(f"\n🔍 Processing length {length}...")

                # Generate password batches
                password_batch = []
                for candidate in itertools.product(charset, repeat=length):
                    if worker.found:
                        break

                    password = ''.join(candidate)
                    password_batch.append(password)

                    # When batch is full, submit to thread pool
                    if len(password_batch) >= batch_size:
                        future = executor.submit(worker.test_password_batch, password_batch.copy())
                        futures.append(future)
                        password_batch = []

                # Submit remaining passwords in the batch
                if password_batch and not worker.found:
                    future = executor.submit(worker.test_password_batch, password_batch)
                    futures.append(future)

            # Wait for completion with progress updates
            for future in as_completed(futures):
                if worker.found:
                    # Cancel remaining futures for faster cleanup
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    break

                # Update progress with completed work
                result, batch_attempts = future.result()
                progress_tracker.update(batch_attempts)

    except KeyboardInterrupt:
        print("\n⚠️  Attack interrupted by user.")
        return None
    finally:
        # Stop progress monitoring
        progress_monitor.stop()

    # Calculate final statistics
    elapsed = time.time() - start_time
    final_stats = progress_tracker.get_final_stats()

    if worker.result:
        print(f"\n✅ PASSWORD CRACKED: '{worker.result}'")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"🔢 Attempts: {final_stats['attempts']:,}")
        print(f"⚡ Average rate: {final_stats['average_rate']:.0f} passwords/sec")
        print(f"🧵 Threads: {num_threads}")
        return worker.result
    else:
        print(f"\n❌ Attack completed without success")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"🔢 Total attempts: {final_stats['attempts']:,}")
        return None


def brute_force_attack_enhanced(target_hash: str, salt: str | None = None, algo: str = 'sha256',
                               max_length: int = 4, charset: str | None = None, num_threads: int = 4):
    """
    Enhanced multithreaded brute-force attack with advanced progress indicators and optimizations.

    Args:
        target_hash: The hash to crack
        salt: Salt for the hash (required for SHA-256)
        algo: Algorithm used ('sha256' or 'bcrypt')
        max_length: Maximum password length to try
        charset: Character set to use (default: lowercase letters + digits)
        num_threads: Number of threads to use

    Returns:
        Cracked password or None if not found
    """
    if charset is None:
        charset = string.ascii_lowercase + string.digits

    print(f"🌟 Starting ENHANCED multithreaded brute-force attack")
    print(f"🧵 Threads: {num_threads} | 📏 Max length: {max_length} | 🔤 Charset: {len(charset)} chars")

    worker = BruteForceWorker(target_hash, salt, algo)
    total_combinations = sum(len(charset) ** length for length in range(1, max_length + 1))

    print(f"🔢 Total combinations: {total_combinations:,}")

    # Estimate time based on combinations
    if total_combinations < 1000:
        estimate = "⚡ Very fast (< 1 second)"
    elif total_combinations < 100000:
        estimate = "🚀 Fast (few seconds)"
    elif total_combinations < 1000000:
        estimate = "⏳ Moderate (may take minutes)"
    else:
        estimate = "🐌 Slow (may take a long time)"

    print(f"⏱️  Estimated time: {estimate}")

    # Initialize advanced progress tracking with faster updates
    progress_tracker = ThreadSafeProgressTracker(total_combinations, num_threads, update_interval=0.2)
    progress_monitor = ProgressMonitor(progress_tracker, stop_condition=lambda: worker.found)

    start_time = time.time()
    # Smaller batches for smoother progress updates
    batch_size = max(25, min(500, total_combinations // (num_threads * 40)))

    print(f"📦 Using batch size: {batch_size} for optimal progress tracking")

    try:
        # Start progress monitoring
        progress_monitor.start()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []

            for length in range(1, max_length + 1):
                if worker.found:
                    break

                print(f"\n📐 Processing length {length}...")

                # Generate password batches
                password_batch = []
                for candidate in itertools.product(charset, repeat=length):
                    if worker.found:
                        break

                    password = ''.join(candidate)
                    password_batch.append(password)

                    # When batch is full, submit to thread pool
                    if len(password_batch) >= batch_size:
                        future = executor.submit(worker.test_password_batch, password_batch.copy())
                        futures.append(future)
                        password_batch = []

                # Submit remaining passwords in the batch
                if password_batch and not worker.found:
                    future = executor.submit(worker.test_password_batch, password_batch)
                    futures.append(future)

            # Wait for completion and collect results
            for future in as_completed(futures):
                if worker.found:
                    # Password found! Cancel remaining futures
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    break

                # Update progress with completed work
                result, attempts = future.result()
                progress_tracker.update(attempts)

    except KeyboardInterrupt:
        print("\n⚠️  Attack interrupted by user.")
        return None
    finally:
        # Stop progress monitoring
        progress_monitor.stop()

    # Calculate final statistics
    elapsed = time.time() - start_time
    final_stats = progress_tracker.get_final_stats()

    # Clear progress line
    print(f"\r{' ' * 100}")

    if worker.result:
        print(f"✅ PASSWORD CRACKED: '{worker.result}'")
        print(f"🎯 Attempts: {final_stats['attempts']:,}")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"🚀 Average rate: {final_stats['average_rate']:.0f} passwords/second")
        print(f"🧵 Threads used: {num_threads}")
        print(f"💯 Search completion: {final_stats['completion_rate']*100:.1f}%")
        return worker.result
    else:
        print(f"❌ Password not found after exhaustive search")
        print(f"🎯 Total attempts: {final_stats['attempts']:,}")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"🚀 Average rate: {final_stats['average_rate']:.0f} passwords/second")
        print(f"🧵 Threads used: {num_threads}")
        return None


if __name__ == "__main__":
    # Test with a simple password
    test_password = "abc"
    result = hash_password_sha256(test_password)
    print(f"Testing with password: {test_password}")

    print("\n=== Testing Single-threaded ===")
    cracked = brute_force_attack(result['hash'], result['salt'], 'sha256', 3)
    print(f"Result: {cracked}")

    print("\n=== Testing Enhanced Multithreaded ===")
    cracked = brute_force_attack_enhanced(result['hash'], result['salt'], 'sha256', 3, None, 4)
    print(f"Result: {cracked}")
