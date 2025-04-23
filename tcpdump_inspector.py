#!/usr/bin/env python3
# tcpdump_inspector.py
# A simple script to capture and print raw tcpdump output for inspection.

import subprocess
import os
import sys
import time

# --- Configuration ---
# !!! CHANGE THIS to your Pi's actual network interface !!!
# (Use 'ip addr' or 'ifconfig' in the terminal to find it, e.g., "eth0", "wlan0")
INTERFACE = "eth0"

# Number of packets to capture in this test run
PACKET_COUNT = 20

# --- End Configuration ---

print(f"--- TCPDump Output Inspector ---")
print(f"Interface:     {INTERFACE}")
print(f"Packet Count:  {PACKET_COUNT}")
print("-" * 30)

# Check for root privileges - tcpdump needs them
if os.geteuid() != 0:
    print("[!] WARNING: This script needs root privileges to run tcpdump.")
    print("    Please execute it using: sudo python3 tcpdump_inspector.py")
    sys.exit(1) # Exit if not root

# Build the tcpdump command arguments
# -i: interface
# -c: count (stop after N packets)
# -n: no hostname resolution (shows raw IPs)
# -nn: no hostname or port name resolution (shows raw ports) - useful!
# -l: line-buffered output (important for piping to script)
# -q: quiet (less verbose output, focuses on packet lines)
# ip: filter to show only IP packets (avoids ARP, etc.)
cmd = [
    "tcpdump",
    "-i", INTERFACE,
    "-c", str(PACKET_COUNT),
    "-nn", # Use -nn to ensure ports are numbers
    "-l",
    "-q",
    "ip"
]

print(f"[*] Running command: {' '.join(cmd)}")
print("[*] Waiting for packets... (Press Ctrl+C to stop early if needed)")
print("-" * 30)

try:
    # Start the tcpdump process
    # Use text=True for automatic decoding, bufsize=1 for line buffering
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    # Read and print output line by line as it arrives
    line_count = 0
    while True:
        output_line = process.stdout.readline()
        if not output_line and process.poll() is not None:
            # Process has finished and no more output
            break
        if output_line:
            line_count += 1
            print(f"[{line_count:02d}] RAW: {output_line.strip()}")

    # Wait for the process to fully terminate and capture any remaining stderr
    process.wait()
    stderr_output = process.stderr.read()

    print("-" * 30)
    print(f"[*] tcpdump finished. Captured approximately {line_count} lines.")

    # Check if tcpdump reported errors
    if process.returncode != 0:
        print(f"[!] tcpdump exited with error code {process.returncode}.")
        if stderr_output:
            print("--- Error Output (stderr) ---")
            print(stderr_output.strip())
            print("---------------------------")
    elif stderr_output: # Print informational stderr messages too (like packets captured count)
        print("[i] tcpdump stderr output:")
        print(stderr_output.strip())
        print("-" * 30)


except FileNotFoundError:
    print(f"[-] ERROR: 'tcpdump' command not found.")
    print(f"    Is it installed? Try: sudo apt-get update && sudo apt-get install tcpdump")
except Exception as e:
    print(f"[-] An unexpected error occurred: {e}")
    # Ensure process is cleaned up if it's still running
    if 'process' in locals() and process.poll() is None:
        print("[!] Terminating potentially running tcpdump process...")
        process.terminate()
        time.sleep(0.5) # Give it a moment
        if process.poll() is None: # If still running
             process.kill()
        process.wait()

print("[*] Inspection script finished.")
