"""
brute_force_safe.py - Safer brute-force attack module with reduced threading complexity

This version focuses on stability over advanced features to avoid race conditions and freezing.
"""
import itertools
import string
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.hash_utils import hash_password_sha256, verify_password_sha256
try:
    from src.bcrypt_utils import verify_password_bcrypt
    bcrypt_available = True
except ImportError:
    bcrypt_available = False


class SafeBruteForceWorker:
    """Simplified worker class with minimal shared state."""

    def __init__(self, target_hash: str, salt: str | None, algo: str):
        self.target_hash = target_hash
        self.salt = salt
        self.algo = algo
        self._found = threading.Event()  # Use Event instead of boolean + lock
        self.result = None
        self._result_lock = threading.Lock()

    @property
    def found(self):
        return self._found.is_set()

    def set_found(self, password: str):
        """Thread-safe method to set the found result."""
        with self._result_lock:
            if not self._found.is_set():
                self.result = password
                self._found.set()

    def test_password_batch(self, password_batch: list[str]) -> tuple[str | None, int]:
        """Test a batch of passwords. Returns (cracked_password, attempts_made)."""
        local_attempts = 0

        for password in password_batch:
            # Check if another thread found the password
            if self._found.is_set():
                return None, local_attempts

            local_attempts += 1

            # Test password
            try:
                if self.algo == 'sha256' and self.salt:
                    if verify_password_sha256(password, self.salt, self.target_hash):
                        self.set_found(password)
                        return password, local_attempts
                elif self.algo == 'bcrypt' and bcrypt_available:
                    if verify_password_bcrypt(password, self.target_hash):
                        self.set_found(password)
                        return password, local_attempts
            except Exception as e:
                # Skip problematic passwords instead of crashing
                print(f"Error testing password '{password}': {e}")
                continue

        return None, local_attempts


def simple_progress_display(current: int, total: int, start_time: float, rate: float = 0):
    """Simple progress display without complex threading."""
    if total > 1000:
        # Progress bar for large searches
        progress = min(current / total, 1.0)
        filled = int(40 * progress)
        bar = '█' * filled + '░' * (40 - filled)
        percentage = progress * 100
        elapsed = time.time() - start_time
        return f"\r[{bar}] {percentage:.1f}% | {current:,}/{total:,} | {rate:.0f}/s | {elapsed:.1f}s"
    else:
        # Simple counter for small searches
        elapsed = time.time() - start_time
        return f"\rTesting... {current:,} attempts | {rate:.0f}/s | {elapsed:.1f}s"


def brute_force_attack(target_hash: str, salt: str | None = None, algo: str = 'sha256',
                      max_length: int = 4, charset: str | None = None):
    """
    Single-threaded brute-force attack (safest option).
    """
    if charset is None:
        charset = string.ascii_lowercase + string.digits

    print(f"🚀 Starting single-threaded brute-force attack")
    print(f"📏 Max length: {max_length} | 🔤 Charset: {len(charset)} chars")

    total_combinations = sum(len(charset) ** length for length in range(1, max_length + 1))
    print(f"🔢 Total combinations: {total_combinations:,}")

    attempts = 0
    start_time = time.time()
    last_display = 0

    try:
        for length in range(1, max_length + 1):
            length_combinations = len(charset) ** length
            print(f"\n🔍 Trying passwords of length {length} ({length_combinations:,} combinations)")

            for candidate in itertools.product(charset, repeat=length):
                password = ''.join(candidate)
                attempts += 1

                # Test password
                try:
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
                except Exception as e:
                    print(f"Error testing password '{password}': {e}")
                    continue

                # Update progress display periodically
                current_time = time.time()
                if current_time - last_display >= 1.0:  # Update every second
                    rate = attempts / (current_time - start_time) if current_time > start_time else 0
                    progress_str = simple_progress_display(attempts, total_combinations, start_time, rate)
                    sys.stdout.write(progress_str)
                    sys.stdout.flush()
                    last_display = current_time

    except KeyboardInterrupt:
        print("\n⚠️  Attack interrupted by user.")
        return None

    elapsed = time.time() - start_time
    print(f"\n❌ Attack completed without success")
    print(f"⏱️  Time: {elapsed:.2f} seconds")
    print(f"🔢 Total attempts: {attempts:,}")
    return None


def brute_force_attack_threaded_safe(target_hash: str, salt: str | None = None, algo: str = 'sha256',
                                    max_length: int = 4, charset: str | None = None, num_threads: int = 4):
    """
    Safer multithreaded brute-force attack with reduced complexity.
    """
    if charset is None:
        charset = string.ascii_lowercase + string.digits

    # Limit thread count to prevent resource exhaustion
    num_threads = min(num_threads, 8)  # Cap at 8 threads max

    print(f"🚀 Starting SAFE multithreaded brute-force attack ({num_threads} threads)")
    print(f"📏 Max length: {max_length} | 🔤 Charset: {len(charset)} chars")

    worker = SafeBruteForceWorker(target_hash, salt, algo)
    total_combinations = sum(len(charset) ** length for length in range(1, max_length + 1))
    print(f"🔢 Total combinations: {total_combinations:,}")

    # Use larger batch sizes to reduce overhead
    batch_size = max(500, total_combinations // (num_threads * 5))
    print(f"📦 Batch size: {batch_size}")

    start_time = time.time()
    total_attempts = 0
    last_display = 0

    try:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            # Pre-generate all work batches to avoid complex iteration in threads
            print("🔄 Generating work batches...")
            all_batches = []

            for length in range(1, max_length + 1):
                print(f"📐 Preparing length {length}...")
                current_batch = []

                for candidate in itertools.product(charset, repeat=length):
                    password = ''.join(candidate)
                    current_batch.append(password)

                    if len(current_batch) >= batch_size:
                        all_batches.append(current_batch.copy())
                        current_batch = []

                # Add remaining passwords
                if current_batch:
                    all_batches.append(current_batch)

            print(f"📊 Generated {len(all_batches)} batches")
            print("🚀 Starting attack...")

            # Submit all batches
            future_to_batch = {
                executor.submit(worker.test_password_batch, batch): i
                for i, batch in enumerate(all_batches)
            }

            # Process results
            for future in as_completed(future_to_batch):
                if worker.found:
                    # Cancel remaining work
                    for f in future_to_batch:
                        f.cancel()
                    break

                # Get result
                try:
                    result, batch_attempts = future.result(timeout=30)  # 30 second timeout per batch
                    total_attempts += batch_attempts

                    # Update progress display
                    current_time = time.time()
                    if current_time - last_display >= 2.0:  # Update every 2 seconds
                        rate = total_attempts / (current_time - start_time) if current_time > start_time else 0
                        progress_str = simple_progress_display(total_attempts, total_combinations, start_time, rate)
                        sys.stdout.write(progress_str)
                        sys.stdout.flush()
                        last_display = current_time

                except Exception as e:
                    print(f"Batch processing error: {e}")
                    continue

    except KeyboardInterrupt:
        print("\n⚠️  Attack interrupted by user.")
        return None
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return None

    # Final results
    elapsed = time.time() - start_time
    rate = total_attempts / elapsed if elapsed > 0 else 0

    if worker.result:
        print(f"\n✅ PASSWORD CRACKED: '{worker.result}'")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"🔢 Attempts: {total_attempts:,}")
        print(f"⚡ Rate: {rate:.0f} passwords/second")
        print(f"🧵 Threads: {num_threads}")
        return worker.result
    else:
        print(f"\n❌ Attack completed without success")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"🔢 Total attempts: {total_attempts:,}")
        print(f"⚡ Rate: {rate:.0f} passwords/second")
        return None


# Alias the safe version as the enhanced version for now
brute_force_attack_enhanced = brute_force_attack_threaded_safe


if __name__ == "__main__":
    # Test with a simple password
    test_password = "abc"
    result = hash_password_sha256(test_password)
    print(f"Testing with password: {test_password}")

    print("\n=== Testing Single-threaded ===")
    cracked = brute_force_attack(result['hash'], result['salt'], 'sha256', 3)
    print(f"Result: {cracked}")

    print("\n=== Testing Safe Multithreaded ===")
    cracked = brute_force_attack_threaded_safe(result['hash'], result['salt'], 'sha256', 3, None, 4)
    print(f"Result: {cracked}")
