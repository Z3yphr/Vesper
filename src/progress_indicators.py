"""
progress_indicators.py - Advanced progress tracking and loading indicators for multithreaded operations

Provides lightweight, thread-safe progress tracking with minimal resource overhead.
"""
import time
import threading
import sys
from typing import Optional, Callable, Any
from dataclasses import dataclass


@dataclass
class ProgressStats:
    """Statistics for progress tracking."""
    attempts: int = 0
    start_time: float = 0
    last_rate_calc: float = 0
    last_attempts: int = 0
    estimated_rate: float = 0


class ThreadSafeProgressTracker:
    """
    Ultra-lightweight progress tracker optimized for multithreaded operations.

    Uses minimal locking and efficient update strategies to avoid performance impact.
    """

    def __init__(self, total_work: int, num_threads: int, update_interval: float = 0.5):
        """
        Initialize progress tracker.

        Args:
            total_work: Total amount of work to be done
            num_threads: Number of worker threads
            update_interval: How often to update display (seconds)
        """
        self.total_work = total_work
        self.num_threads = num_threads
        self.update_interval = update_interval

        # Thread-safe counters
        self._stats = ProgressStats()
        self._lock = threading.RLock()  # Reentrant lock for nested calls

        # Display control
        self.active = True
        self.last_display_time = 0

        # Visual elements
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.progress_chars = ['█', '▉', '▊', '▋', '▌', '▍', '▎', '▏', '░']

    def start(self):
        """Start tracking progress."""
        with self._lock:
            self._stats.start_time = time.time()
            self._stats.last_rate_calc = self._stats.start_time

    def update(self, work_completed: int):
        """
        Update progress counter (thread-safe).

        Args:
            work_completed: Amount of new work completed since last update
        """
        current_time = time.time()

        with self._lock:
            self._stats.attempts += work_completed

            # Calculate rate every second to avoid excessive computation
            if current_time - self._stats.last_rate_calc >= 1.0:
                time_delta = current_time - self._stats.last_rate_calc
                attempts_delta = self._stats.attempts - self._stats.last_attempts

                if time_delta > 0:
                    # Exponential smoothing for rate calculation
                    new_rate = attempts_delta / time_delta
                    self._stats.estimated_rate = (0.7 * self._stats.estimated_rate + 0.3 * new_rate)

                self._stats.last_rate_calc = current_time
                self._stats.last_attempts = self._stats.attempts

    def should_display_update(self) -> bool:
        """Check if it's time to update the display (reduces flickering)."""
        current_time = time.time()
        if current_time - self.last_display_time >= self.update_interval:
            self.last_display_time = current_time
            return True
        return False

    def get_progress_display(self, use_progress_bar: bool = None) -> str:
        """
        Generate progress display string.

        Args:
            use_progress_bar: Force progress bar (True) or spinner (False).
                            None = auto-detect based on total work.

        Returns:
            Formatted progress string
        """
        with self._lock:
            current_time = time.time()
            elapsed = current_time - self._stats.start_time

            # Auto-detect display type if not specified
            if use_progress_bar is None:
                use_progress_bar = self.total_work > 1000

            if use_progress_bar and self.total_work > 0:
                display = self._generate_progress_bar(elapsed)
            else:
                display = self._generate_spinner(elapsed)

            # Pad the display to clear any leftover characters from previous output
            return display.ljust(100)

    def _generate_progress_bar(self, elapsed: float) -> str:
        """Generate a detailed progress bar."""
        progress = min(self._stats.attempts / self.total_work, 1.0)

        # Create smooth progress bar
        bar_width = 40
        filled_width = progress * bar_width
        filled_blocks = int(filled_width)
        partial_block = filled_width - filled_blocks

        # Build bar with smooth partial blocks
        bar = '█' * filled_blocks
        if filled_blocks < bar_width and partial_block > 0:
            partial_index = int(partial_block * 8)
            bar += ['▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'][partial_index]
            filled_blocks += 1
        bar += '░' * (bar_width - filled_blocks)

        percentage = progress * 100

        # Estimate time remaining
        if self._stats.estimated_rate > 0 and progress > 0:
            remaining_work = self.total_work - self._stats.attempts
            eta_seconds = remaining_work / self._stats.estimated_rate
            eta_str = self._format_time(eta_seconds)
        else:
            eta_str = "calculating..."

        return (f"\r[{bar}] {percentage:.1f}% | "
                f"{self._stats.attempts:,}/{self.total_work:,} | "
                f"{self._stats.estimated_rate:.0f}/s | "
                f"{self.num_threads}T | "
                f"ETA: {eta_str}")

    def _generate_spinner(self, elapsed: float) -> str:
        """Generate an animated spinner display."""
        spinner_index = int(time.time() * 8) % len(self.spinner_chars)
        spinner = self.spinner_chars[spinner_index]

        return (f"\r{spinner} Working... {self._stats.attempts:,} completed | "
                f"{self._stats.estimated_rate:.0f}/s | "
                f"{self.num_threads} threads | "
                f"{self._format_time(elapsed)}")

    def _format_time(self, seconds: float) -> str:
        """Format time duration."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.0f}m{seconds%60:.0f}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h{minutes}m"

    def get_final_stats(self) -> dict:
        """Get final statistics."""
        with self._lock:
            elapsed = time.time() - self._stats.start_time
            avg_rate = self._stats.attempts / elapsed if elapsed > 0 else 0

            return {
                'attempts': self._stats.attempts,
                'elapsed_time': elapsed,
                'average_rate': avg_rate,
                'num_threads': self.num_threads,
                'completion_rate': self._stats.attempts / self.total_work if self.total_work > 0 else 0
            }


class ProgressMonitor:
    """
    Background progress monitor that runs in a separate thread.

    This is very lightweight and only wakes up periodically to update the display.
    """

    def __init__(self, tracker: ThreadSafeProgressTracker, stop_condition: Callable[[], bool] = None):
        """
        Initialize progress monitor.

        Args:
            tracker: Progress tracker to monitor
            stop_condition: Function that returns True when monitoring should stop
        """
        self.tracker = tracker
        self.stop_condition = stop_condition or (lambda: not tracker.active)
        self._monitor_thread = None

    def start(self):
        """Start the background monitor thread."""
        self.tracker.start()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop(self):
        """Stop the background monitor."""
        self.tracker.active = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=1.0)

    def _monitor_loop(self):
        """Main monitoring loop (runs in background thread)."""
        while self.tracker.active and not self.stop_condition():
            if self.tracker.should_display_update():
                try:
                    progress_str = self.tracker.get_progress_display()
                    sys.stdout.write(progress_str)
                    sys.stdout.flush()
                except:
                    # Ignore display errors (e.g., if output is redirected)
                    pass

            # Sleep to avoid excessive CPU usage
            time.sleep(0.1)


class SimpleSpinner:
    """Ultra-simple spinner for quick operations (no threading required)."""

    def __init__(self, message: str = "Working"):
        self.message = message
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.counter = 0

    def tick(self):
        """Update the spinner (call this periodically from your main thread)."""
        spinner = self.spinner_chars[self.counter % len(self.spinner_chars)]
        sys.stdout.write(f"\r{spinner} {self.message}...")
        sys.stdout.flush()
        self.counter += 1

    def finish(self, final_message: str = "Done"):
        """Finish the spinner with a final message."""
        sys.stdout.write(f"\r✓ {final_message}\n")
        sys.stdout.flush()


# Example usage functions
def demo_progress_tracker():
    """Demonstrate the progress tracker with a simulated multithreaded operation."""
    import random
    from concurrent.futures import ThreadPoolExecutor, as_completed

    total_work = 10000
    num_threads = 4

    print("Demo: Multithreaded Progress Tracking")
    print(f"Simulating {total_work:,} operations across {num_threads} threads")

    # Initialize tracker and monitor
    tracker = ThreadSafeProgressTracker(total_work, num_threads)
    monitor = ProgressMonitor(tracker)

    def worker_task(work_batch: int) -> int:
        """Simulate work and return number of items processed."""
        # Simulate variable processing time
        time.sleep(random.uniform(0.01, 0.1))
        tracker.update(work_batch)
        return work_batch

    try:
        monitor.start()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            # Submit work in batches
            batch_size = total_work // (num_threads * 10)
            futures = []

            for i in range(0, total_work, batch_size):
                remaining = min(batch_size, total_work - i)
                future = executor.submit(worker_task, remaining)
                futures.append(future)

            # Wait for completion
            for future in as_completed(futures):
                future.result()  # This will raise any exceptions

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    finally:
        monitor.stop()

        # Show final statistics
        stats = tracker.get_final_stats()
        print(f"\n\nFinal Statistics:")
        print(f"✓ Completed: {stats['attempts']:,} operations")
        print(f"⏱ Time: {stats['elapsed_time']:.2f} seconds")
        print(f"⚡ Rate: {stats['average_rate']:.0f} operations/second")
        print(f"🧵 Threads: {stats['num_threads']}")


if __name__ == "__main__":
    demo_progress_tracker()
