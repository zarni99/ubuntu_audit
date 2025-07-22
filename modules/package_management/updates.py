#!/usr/bin/env python3

"""
CIS Ubuntu 22.04 LTS Benchmark - Section 1.2.2 Configure Package Updates

This module provides functions to audit and optionally remediate the package
updates configuration according to CIS Ubuntu 22.04 LTS Benchmark section 1.2.2.

Each audit function:
- Returns pass/fail status
- Includes a remediation suggestion
- Prints meaningful status messages
"""

# ANSI color codes
COLORS = {
    'GREEN': '\033[92m',  # Green for PASS
    'RED': '\033[91m',    # Red for FAIL
    'YELLOW': '\033[93m', # Yellow for warnings
    'BLUE': '\033[94m',   # Blue for section headers
    'RESET': '\033[0m'    # Reset to default color
}

import subprocess
import os
import sys


def _run_command(command):
    """
    Run a shell command and return its output
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        return "", str(e), 1


def check_updates_installed():
    """
    1.2.2.1 Ensure updates, patches, and additional security software are installed (Manual)
    """
    benchmark_id = "1.2.2.1"
    description = "Ensure updates, patches, and additional security software are installed (Manual)"
    
    # Check if there are any pending updates
    stdout, _, _ = _run_command("apt list --upgradable 2>/dev/null | grep -v 'Listing...'")
    
    if not stdout:
        print(f"{COLORS['GREEN']}[+] PASS: All available updates are installed{COLORS['RESET']}")
        print(f"    No pending updates found in the system")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: There are pending updates that need to be installed{COLORS['RESET']}")
    print(f"    Remediation: Run 'sudo apt update && sudo apt upgrade' to install updates")
    print(f"    Number of pending updates: {len(stdout.splitlines())}")
    return False, f"{benchmark_id} {description}", False


def remediate_updates_installed():
    """
    Remediation for 1.2.2.1 Ensure updates, patches, and additional security software are installed
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for installing updates:{COLORS['RESET']}")
    print("1. Update the package lists: sudo apt update")
    print("2. Install all available updates: sudo apt upgrade")
    print("3. For security updates only: sudo apt upgrade -s | grep -i security")
    print("4. Consider setting up automatic updates:")
    print("   a. Install unattended-upgrades: sudo apt install unattended-upgrades")
    print("   b. Configure in /etc/apt/apt.conf.d/50unattended-upgrades")
    print("   c. Enable the service: sudo dpkg-reconfigure -plow unattended-upgrades")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit package_management")
    return True


def run_all_audits(return_results=False):
    """
    Run all audit checks for this module
    
    Args:
        return_results: If True, return a list of results instead of just True/False
    
    Returns:
        If return_results is True, returns a list of tuples (benchmark_id, description, result)
        Otherwise, returns True if all checks pass, False otherwise
    """
    results = []
    
    # Run all check functions
    updates_result = check_updates_installed()
    results.append(updates_result)
    
    # If we need to return detailed results
    if return_results:
        return results
    
    # Otherwise, return True only if all checks passed
    return all(result[2] for result in results)


def run_all_remediations():
    """
    Run all remediation functions for this module
    """
    success = True
    
    # Run all remediation functions
    if not remediate_updates_installed():
        success = False
    
    return success