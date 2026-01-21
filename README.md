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

https://www.openwall.com/lists/oss-security/2026/01/20/2
