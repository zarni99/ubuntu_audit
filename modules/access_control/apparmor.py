#!/usr/bin/env python3

"""
CIS Ubuntu 22.04 LTS Benchmark - Section 1.3.1 Configure AppArmor

This module provides functions to audit and optionally remediate the AppArmor
configuration according to CIS Ubuntu 22.04 LTS Benchmark section 1.3.1.

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


def check_apparmor_installed():
    """
    1.3.1.1 Ensure AppArmor is installed (Automated)
    """
    benchmark_id = "1.3.1.1"
    description = "Ensure AppArmor is installed (Automated)"
    
    # Check if AppArmor is installed
    stdout, _, _ = _run_command("dpkg -s apparmor apparmor-utils 2>/dev/null | grep -E '^Status: install'")
    
    if len(stdout.splitlines()) >= 2:  # Both packages should be installed
        print(f"{COLORS['GREEN']}[+] PASS: AppArmor and AppArmor utilities are installed{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: AppArmor and/or AppArmor utilities are not installed{COLORS['RESET']}")
    print(f"    Remediation: Run 'sudo apt install apparmor apparmor-utils'")
    return False, f"{benchmark_id} {description}", False


def check_apparmor_enabled_bootloader():
    """
    1.3.1.2 Ensure AppArmor is enabled in the bootloader configuration (Automated)
    """
    benchmark_id = "1.3.1.2"
    description = "Ensure AppArmor is enabled in the bootloader configuration (Automated)"
    
    # Check if AppArmor is enabled in the bootloader
    stdout, _, _ = _run_command("grep -E '^GRUB_CMDLINE_LINUX=' /etc/default/grub")
    
    if "apparmor=1" in stdout and "security=apparmor" in stdout:
        print(f"{COLORS['GREEN']}[+] PASS: AppArmor is enabled in the bootloader configuration{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: AppArmor is not enabled in the bootloader configuration{COLORS['RESET']}")
    print(f"    Remediation: Add 'apparmor=1 security=apparmor' to GRUB_CMDLINE_LINUX in /etc/default/grub")
    print(f"    Then run 'sudo update-grub' to update the bootloader configuration")
    return False, f"{benchmark_id} {description}", False


def check_apparmor_profiles_enforcing():
    """
    1.3.1.3 Ensure all AppArmor Profiles are in enforce or complain mode (Automated)
    """
    benchmark_id = "1.3.1.3"
    description = "Ensure all AppArmor Profiles are in enforce or complain mode (Automated)"
    
    # Check if any profiles are in complain mode
    stdout, _, _ = _run_command("apparmor_status 2>/dev/null | grep -E '^([0-9]+) profiles are in complain mode'")
    complain_count = 0
    if stdout:
        complain_count = int(stdout.split()[0])
    
    # Check if any profiles are in enforce mode
    stdout, _, _ = _run_command("apparmor_status 2>/dev/null | grep -E '^([0-9]+) profiles are in enforce mode'")
    enforce_count = 0
    if stdout:
        enforce_count = int(stdout.split()[0])
    
    # Check if any processes are unconfined
    stdout, _, _ = _run_command("apparmor_status 2>/dev/null | grep -E '^([0-9]+) processes are unconfined'")
    unconfined_count = 0
    if stdout:
        unconfined_count = int(stdout.split()[0])
    
    if enforce_count > 0 or complain_count > 0:
        print(f"{COLORS['GREEN']}[+] PASS: AppArmor profiles are in enforce or complain mode{COLORS['RESET']}")
        print(f"    Profiles in enforce mode: {enforce_count}")
        print(f"    Profiles in complain mode: {complain_count}")
        print(f"    Unconfined processes: {unconfined_count}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: No AppArmor profiles are in enforce or complain mode{COLORS['RESET']}")
    print(f"    Remediation: Enable AppArmor profiles using 'sudo aa-enforce' or 'sudo aa-complain'")
    return False, f"{benchmark_id} {description}", False


def remediate_apparmor_installed():
    """
    Remediation for 1.3.1.1 Ensure AppArmor is installed
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for installing AppArmor:{COLORS['RESET']}")
    print("1. Install AppArmor and AppArmor utilities:")
    print("   sudo apt update")
    print("   sudo apt install -y apparmor apparmor-utils")
    print("2. Verify installation:")
    print("   dpkg -s apparmor apparmor-utils | grep Status")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit access_control")
    return True


def remediate_apparmor_enabled_bootloader():
    """
    Remediation for 1.3.1.2 Ensure AppArmor is enabled in the bootloader configuration
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for enabling AppArmor in bootloader:{COLORS['RESET']}")
    print("1. Edit the GRUB configuration:")
    print("   sudo nano /etc/default/grub")
    print("2. Add 'apparmor=1 security=apparmor' to GRUB_CMDLINE_LINUX if not already present:")
    print("   GRUB_CMDLINE_LINUX=\"apparmor=1 security=apparmor\"")
    print("   (If other options exist, add these parameters to the existing line)")
    print("3. Update GRUB configuration:")
    print("   sudo update-grub")
    print("4. Reboot the system to apply changes:")
    print("   sudo reboot")
    
    print(f"\n{COLORS['YELLOW']}After making these changes and rebooting, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit access_control")
    return True


def remediate_apparmor_profiles_enforcing():
    """
    Remediation for 1.3.1.3 Ensure all AppArmor Profiles are in enforce or complain mode
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for enabling AppArmor profiles:{COLORS['RESET']}")
    print("1. List available profiles:")
    print("   sudo aa-status")
    print("2. Set profiles to enforce mode (recommended for production):")
    print("   sudo aa-enforce /etc/apparmor.d/*")
    print("   OR for specific profiles:")
    print("   sudo aa-enforce /etc/apparmor.d/profile_name")
    print("3. Alternatively, set profiles to complain mode (for testing):")
    print("   sudo aa-complain /etc/apparmor.d/*")
    print("4. Restart AppArmor service:")
    print("   sudo systemctl restart apparmor")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit access_control")
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
    installed_result = check_apparmor_installed()
    results.append(installed_result)
    
    bootloader_result = check_apparmor_enabled_bootloader()
    results.append(bootloader_result)
    
    profiles_result = check_apparmor_profiles_enforcing()
    results.append(profiles_result)
    
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
    if not remediate_apparmor_installed():
        success = False
    
    if not remediate_apparmor_enabled_bootloader():
        success = False
    
    if not remediate_apparmor_profiles_enforcing():
        success = False
    
    return success