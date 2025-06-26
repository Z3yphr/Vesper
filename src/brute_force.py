"""
brute_force.py - Brute-force attack module for Vesper

Provides functions for brute-force attacks on password hashes.
"""
import itertools
import string
import sys
import time
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.hash_utils import hash_password_sha256, verify_password_sha256
try:
    from src.bcrypt_utils import verify_password_bcrypt
    bcrypt_available = True
except ImportError:
    bcrypt_available = False

def show_progress_bar(current: int, total: int, width: int = 50) -> str:
    """Generate a progress bar string."""
    progress = current / total
    filled = int(width * progress)
    bar = '█' * filled + '░' * (width - filled)
    percentage = progress * 100
    return f"[{bar}] {percentage:.1f}% ({current:,}/{total:,})"

def show_spinner(attempts: int) -> None:
    """Show a spinning animation with attempt count."""
    spinner_chars = ['|', '/', '-', '\\']
    spinner = spinner_chars[attempts % 4]
    sys.stdout.write(f"\r{spinner} Trying passwords... {attempts:,} attempts")
    sys.stdout.flush()

class BruteForceWorker:
    """Worker class for multithreaded brute-force attacks."""

    def __init__(self, target_hash: str, salt: str | None, algo: str):
        self.target_hash = target_hash
        self.salt = salt
        self.algo = algo
        self.found = False
        self.result = None
        self.attempts = 0
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
        
        # Update global attempt counter
        with self.lock:
            self.attempts += local_attempts
            
        return None, local_attempts

class ProgressTracker:
    """Thread-safe progress tracking for multithreaded operations."""
    
    def __init__(self, total_combinations: int, num_threads: int):
        self.total_combinations = total_combinations
        self.num_threads = num_threads
        self.attempts = 0
        self.start_time = time.time()
        self.last_update = 0
        self.lock = threading.Lock()
        self.active = True
        
    def update_progress(self, new_attempts: int):
        """Update progress with new attempt count."""
        with self.lock:
            self.attempts += new_attempts
            
    def should_display(self) -> bool:
        """Check if progress should be displayed (to avoid spam)."""
        current_time = time.time()
        with self.lock:
            if current_time - self.last_update >= 0.5:  # Update every 0.5 seconds
                self.last_update = current_time
                return True
        return False
        
    def get_progress_string(self) -> str:
        """Get current progress as a formatted string."""
        with self.lock:
            elapsed = time.time() - self.start_time
            rate = self.attempts / elapsed if elapsed > 0 else 0
            
            if self.total_combinations > 10000:
                progress_bar = show_progress_bar(self.attempts, self.total_combinations)
                return f"\r{progress_bar} | {rate:.0f} pwd/s | {self.num_threads} threads"
            else:
                spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
                spinner = spinner_chars[int(time.time() * 10) % len(spinner_chars)]
                return f"\r{spinner} Testing passwords... {self.attempts:,} attempts | {rate:.0f} pwd/s | {self.num_threads} threads"

def progress_monitor(tracker: ProgressTracker, worker: BruteForceWorker):
    """Background thread to display progress updates."""
    while tracker.active and not worker.found:
        if tracker.should_display():
            progress_str = tracker.get_progress_string()
            sys.stdout.write(progress_str)
            sys.stdout.flush()
        time.sleep(0.1)  # Small sleep to prevent excessive CPU usage

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
    total_combinations = sum(len(charset) ** length for length in range(1, max_length + 1))

    print(f"Total combinations to try: {total_combinations:,}")
    print("Progress:")

    start_time = time.time()
    last_update = 0

    for length in range(1, max_length + 1):
        length_combinations = len(charset) ** length
        print(f"\nTrying passwords of length {length} ({length_combinations:,} combinations):")

        for i, candidate in enumerate(itertools.product(charset, repeat=length)):
            password = ''.join(candidate)
            attempts += 1

            # Check if password matches
            if algo == 'sha256' and salt:
                if verify_password_sha256(password, salt, target_hash):
                    elapsed = time.time() - start_time
                    print(f"\n✓ PASSWORD CRACKED in {attempts:,} attempts ({elapsed:.2f}s): {password}")
                    return password
            elif algo == 'bcrypt' and bcrypt_available:
                if verify_password_bcrypt(password, target_hash):
                    elapsed = time.time() - start_time
                    print(f"\n✓ PASSWORD CRACKED in {attempts:,} attempts ({elapsed:.2f}s): {password}")
                    return password

            # Update progress every 100 attempts or every second
            current_time = time.time()
            if attempts % 100 == 0 or current_time - last_update >= 1:
                if total_combinations > 1000:
                    # Show progress bar for large searches
                    progress_bar = show_progress_bar(attempts, total_combinations)
                    elapsed = current_time - start_time
                    rate = attempts / elapsed if elapsed > 0 else 0
                    print(f"\r{progress_bar} | {rate:.0f} passwords/sec", end="")
                else:
                    # Show spinner for smaller searches
                    show_spinner(attempts)
                last_update = current_time

    elapsed = time.time() - start_time
    print(f"\n\n❌ Attack completed. Password not found after {attempts:,} attempts ({elapsed:.2f}s)")
    return None

def brute_force_attack_threaded(target_hash: str, salt: str | None = None, algo: str = 'sha256',
                               max_length: int = 4, charset: str | None = None, num_threads: int = 4):
    """
    Multithreaded brute-force attack on a hash.

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

    print(f"Starting MULTITHREADED brute-force attack ({num_threads} threads)")
    print(f"Max length: {max_length}, charset: {len(charset)} chars")

    worker = BruteForceWorker(target_hash, salt, algo)
    total_combinations = sum(len(charset) ** length for length in range(1, max_length + 1))
    print(f"Total combinations to try: {total_combinations:,}")

    start_time = time.time()
    attempts = 0
    batch_size = max(100, total_combinations // (num_threads * 10))  # Dynamic batch size

    # Initialize progress tracker
    tracker = ProgressTracker(total_combinations, num_threads)
    monitor_thread = threading.Thread(target=progress_monitor, args=(tracker, worker))
    monitor_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []

            for length in range(1, max_length + 1):
                if worker.found:
                    break

                print(f"\nTrying passwords of length {length}...")

                # Generate password batches
                password_batch = []
                for candidate in itertools.product(charset, repeat=length):
                    if worker.found:
                        break

                    password = ''.join(candidate)
                    password_batch.append(password)
                    attempts += 1

                    # When batch is full, submit to thread pool
                    if len(password_batch) >= batch_size:
                        future = executor.submit(worker.test_password_batch, password_batch.copy())
                        futures.append(future)
                        password_batch = []

                        # Progress update
                        if attempts % (batch_size * 5) == 0:
                            elapsed = time.time() - start_time
                            rate = attempts / elapsed if elapsed > 0 else 0
                            tracker.update_progress(attempts - sum(f.result()[1] for f in futures if f.done()))
                            if tracker.should_display():
                                progress_str = tracker.get_progress_string()
                                sys.stdout.write(progress_str)
                                sys.stdout.flush()

                # Submit remaining passwords in the batch
                if password_batch and not worker.found:
                    future = executor.submit(worker.test_password_batch, password_batch)
                    futures.append(future)

            # Wait for completion or success
            for future in as_completed(futures):
                result = future.result()
                if result:
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break

    except KeyboardInterrupt:
        print("\n\nAttack interrupted by user.")
        tracker.active = False
        monitor_thread.join()
        return None

    tracker.active = False
    monitor_thread.join()

    elapsed = time.time() - start_time

    if worker.result:
        print(f"\n✓ PASSWORD CRACKED in {attempts:,} attempts ({elapsed:.2f}s): {worker.result}")
        print(f"Average rate: {attempts/elapsed:.0f} passwords/sec across {num_threads} threads")
        return worker.result
    else:
        print(f"\n❌ Attack completed. Password not found after {attempts:,} attempts ({elapsed:.2f}s)")
        return None

if __name__ == "__main__":
    # Test with a simple password
    test_password = "abc"
    result = hash_password_sha256(test_password)
    print(f"Testing with password: {test_password}")
    cracked = brute_force_attack(result['hash'], result['salt'], 'sha256', 3)
    print(f"Result: {cracked}")
