#!/usr/bin/env python3

"""
CIS Ubuntu 22.04 LTS Benchmark - Section 1.2.1 Configure Package Repositories

This module provides functions to audit and optionally remediate the package
repositories configuration according to CIS Ubuntu 22.04 LTS Benchmark section 1.2.1.

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


def check_gpg_keys():
    """
    1.2.1.1 Ensure GPG keys are configured (Manual)
    """
    benchmark_id = "1.2.1.1"
    description = "Ensure GPG keys are configured (Manual)"
    
    # Check if apt-key is deprecated and if apt-key list shows any keys
    stdout, _, _ = _run_command("apt-key list")
    
    # Check if there are keys in /etc/apt/trusted.gpg.d/
    trusted_gpg_files, _, _ = _run_command("ls -l /etc/apt/trusted.gpg.d/ | grep -E '\.(gpg|asc)$'")
    
    # Check if there are keys defined in sources.list files
    sources_with_keys, _, _ = _run_command("grep -r 'signed-by=' /etc/apt/sources.list /etc/apt/sources.list.d/")
    
    if trusted_gpg_files or sources_with_keys:
        print(f"{COLORS['GREEN']}[+] PASS: GPG keys are properly configured{COLORS['RESET']}")
        print(f"    Found GPG keys in trusted.gpg.d or signed-by directives in sources")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: GPG keys configuration could not be verified{COLORS['RESET']}")
    print(f"    Remediation: Configure GPG keys for all package repositories")
    print(f"    Modern method: Use signed-by in source entries or files in /etc/apt/trusted.gpg.d/")
    return False, f"{benchmark_id} {description}", False


def check_package_manager_repositories():
    """
    1.2.1.2 Ensure package manager repositories are configured (Manual)
    """
    benchmark_id = "1.2.1.2"
    description = "Ensure package manager repositories are configured (Manual)"
    
    # Check if sources.list and sources.list.d have entries
    sources_list, _, _ = _run_command("grep -v '^#' /etc/apt/sources.list | grep -E '^deb '")
    sources_list_d, _, _ = _run_command("grep -v '^#' /etc/apt/sources.list.d/*.list 2>/dev/null | grep -E '^deb '")
    
    if sources_list or sources_list_d:
        print(f"{COLORS['GREEN']}[+] PASS: Package manager repositories are configured{COLORS['RESET']}")
        print(f"    Found active repository entries in sources.list or sources.list.d")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: No package manager repositories configured{COLORS['RESET']}")
    print(f"    Remediation: Configure appropriate repositories in /etc/apt/sources.list")
    print(f"    or in separate files under /etc/apt/sources.list.d/")
    return False, f"{benchmark_id} {description}", False


def remediate_gpg_keys():
    """
    Remediation for 1.2.1.1 Ensure GPG keys are configured
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for GPG keys configuration:{COLORS['RESET']}")
    print("1. Identify the repositories you need to use")
    print("2. For each repository, obtain the GPG key using one of these methods:")
    print("   a. Download the key: sudo wget -qO- https://repo-url/key.gpg | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/repo-name.gpg")
    print("   b. Or use signed-by in source entries: deb [signed-by=/etc/apt/trusted.gpg.d/repo-name.gpg] https://repo-url distribution component")
    print("3. Verify the keys: apt-key list or ls -l /etc/apt/trusted.gpg.d/")
    print("\nNote: apt-key is deprecated. Use the trusted.gpg.d directory or signed-by method instead.")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit package_management")
    return True


def remediate_package_manager_repositories():
    """
    Remediation for 1.2.1.2 Ensure package manager repositories are configured
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for package manager repositories:{COLORS['RESET']}")
    print("1. Edit /etc/apt/sources.list or create files in /etc/apt/sources.list.d/ with appropriate entries")
    print("2. Example for Ubuntu 22.04 (Jammy Jellyfish):")
    print("   deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu/ jammy main restricted universe multiverse")
    print("   deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu/ jammy-updates main restricted universe multiverse")
    print("   deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu/ jammy-security main restricted universe multiverse")
    print("3. Update package lists: sudo apt update")
    
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
    gpg_result = check_gpg_keys()
    results.append(gpg_result)
    
    repo_result = check_package_manager_repositories()
    results.append(repo_result)
    
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
    if not remediate_gpg_keys():
        success = False
    
    if not remediate_package_manager_repositories():
        success = False
    
    return success