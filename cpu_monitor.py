#!/usr/bin/env python3
"""
CPU Monitor Script

This script runs another process and monitors its CPU usage, reporting
the average and highest CPU usage during the process execution.

Usage:
    python cpu_monitor.py <command> [args...]

Example:
    python cpu_monitor.py ls -la
    python cpu_monitor.py ./build/bin/elasticurl --help
"""

import sys
import subprocess
import psutil
import time
import threading
import argparse
from typing import List, Tuple, Optional


class CPUMonitor:
    def __init__(self, sampling_interval: float = 0.1):
        """
        Initialize CPU monitor.

        Args:
            sampling_interval: Time between CPU usage samples in seconds
        """
        self.sampling_interval = sampling_interval
        self.cpu_samples: List[float] = []
        self.monitoring = False
        self.process: Optional[psutil.Process] = None

    def _monitor_cpu(self) -> None:
        """Monitor CPU usage in a separate thread."""
        while self.monitoring and self.process and self.process.is_running():
            try:
                # Get CPU percentage for the specific process
                cpu_percent = self.process.cpu_percent()
                if cpu_percent > 0:  # Only record non-zero values
                    self.cpu_samples.append(cpu_percent)
                time.sleep(self.sampling_interval)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process has ended or we can't access it
                break

    def run_and_monitor(self, command: List[str]) -> Tuple[int, float, float]:
        """
        Run a command and monitor its CPU usage.

        Args:
            command: List of command and arguments to execute

        Returns:
            Tuple of (return_code, average_cpu, max_cpu)
        """
        print(f"Starting process: {' '.join(command)}")
        print(f"Monitoring CPU usage (sampling every {self.sampling_interval}s)...")
        print("-" * 50)

        # Start the process
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        except FileNotFoundError:
            print(f"Error: Command '{command[0]}' not found")
            return 1, 0.0, 0.0
        except Exception as e:
            print(f"Error starting process: {e}")
            return 1, 0.0, 0.0

        # Get psutil process object for monitoring
        try:
            self.process = psutil.Process(process.pid)
        except psutil.NoSuchProcess:
            print("Error: Could not attach to process for monitoring")
            return 1, 0.0, 0.0

        # Start monitoring in a separate thread
        self.monitoring = True
        monitor_thread = threading.Thread(target=self._monitor_cpu, daemon=True)
        monitor_thread.start()

        # Wait for process to complete and capture output
        try:
            stdout, stderr = process.communicate()
            return_code = process.returncode
        except KeyboardInterrupt:
            print("\nInterrupted by user")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            return_code = 130  # Standard exit code for SIGINT
            stdout, stderr = "", ""
        finally:
            # Stop monitoring
            self.monitoring = False
            if monitor_thread.is_alive():
                monitor_thread.join(timeout=1)

        # Print process output
        if stdout:
            print("Process output:")
            print(stdout)
        if stderr:
            print("Process errors:")
            print(stderr, file=sys.stderr)

        # Calculate CPU statistics
        if self.cpu_samples:
            avg_cpu = sum(self.cpu_samples) / len(self.cpu_samples)
            max_cpu = max(self.cpu_samples)
        else:
            avg_cpu = 0.0
            max_cpu = 0.0

        return return_code, avg_cpu, max_cpu


def main():
    """Main function to parse arguments and run the monitor."""
    if len(sys.argv) < 2:
        print("Usage: python cpu_monitor.py <command> [args...]")
        print("\nExample:")
        print("  python cpu_monitor.py ls -la")
        print("  python cpu_monitor.py ./build/bin/elasticurl --help")
        sys.exit(1)

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Monitor CPU usage while running another process",
        add_help=False  # We'll handle help manually since we need to pass through args
    )

    # Check if user wants help
    if '--help' in sys.argv or '-h' in sys.argv:
        parser.print_help()
        sys.exit(0)

    # Get the command to run (everything after the script name)
    command = sys.argv[1:]

    # Create and run the monitor
    monitor = CPUMonitor(sampling_interval=0.1)  # Sample every 100ms

    try:
        return_code, avg_cpu, max_cpu = monitor.run_and_monitor(command)

        # Print results
        print("-" * 50)
        print("CPU Usage Statistics:")
        print(f"  Process exit code: {return_code}")
        print(f"  Average CPU usage: {avg_cpu:.2f}%")
        print(f"  Highest CPU usage: {max_cpu:.2f}%")
        print(f"  Total samples collected: {len(monitor.cpu_samples)}")

        if len(monitor.cpu_samples) == 0:
            print("  Note: No CPU usage data collected (process may have been too short)")

        sys.exit(return_code)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
