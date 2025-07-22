#!/usr/bin/env python3

"""
CIS Ubuntu 22.04 LTS Benchmark - Section 1.4 Configure Bootloader

This module provides functions to audit and optionally remediate the bootloader
configuration according to CIS Ubuntu 22.04 LTS Benchmark section 1.4.

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
import stat


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


def check_bootloader_password():
    """
    1.4.1 Ensure bootloader password is set (Automated)
    """
    benchmark_id = "1.4.1"
    description = "Ensure bootloader password is set (Automated)"
    
    # Check if GRUB password is configured
    stdout, _, _ = _run_command("grep -E '^password|^password_pbkdf2' /boot/grub/grub.cfg")
    
    if stdout:
        print(f"{COLORS['GREEN']}[+] PASS: Bootloader password is set{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: Bootloader password is not set{COLORS['RESET']}")
    print(f"    Remediation: Generate and set a GRUB bootloader password")
    return False, f"{benchmark_id} {description}", False


def check_bootloader_config_permissions():
    """
    1.4.2 Ensure access to bootloader config is configured (Automated)
    """
    benchmark_id = "1.4.2"
    description = "Ensure access to bootloader config is configured (Automated)"
    
    # Check permissions on /boot/grub/grub.cfg
    try:
        grub_stat = os.stat('/boot/grub/grub.cfg')
        grub_mode = grub_stat.st_mode
        grub_owner = grub_stat.st_uid
        grub_group = grub_stat.st_gid
        
        # Check if permissions are 400 (read-only for owner) and owner/group is root
        if (grub_mode & 0o777) == 0o400 and grub_owner == 0 and grub_group == 0:
            print(f"{COLORS['GREEN']}[+] PASS: Bootloader config has secure permissions{COLORS['RESET']}")
            return True, f"{benchmark_id} {description}", True
        
        print(f"{COLORS['RED']}[-] FAIL: Bootloader config has insecure permissions{COLORS['RESET']}")
        print(f"    Current permissions: {oct(grub_mode & 0o777)}")
        print(f"    Current owner/group: {grub_owner}/{grub_group}")
        print(f"    Remediation: Run 'sudo chmod 400 /boot/grub/grub.cfg' and 'sudo chown root:root /boot/grub/grub.cfg'")
        return False, f"{benchmark_id} {description}", False
    
    except FileNotFoundError:
        print(f"{COLORS['RED']}[-] FAIL: Bootloader config file not found{COLORS['RESET']}")
        return False, f"{benchmark_id} {description}", False
    except Exception as e:
        print(f"{COLORS['RED']}[-] FAIL: Error checking bootloader config permissions: {e}{COLORS['RESET']}")
        return False, f"{benchmark_id} {description}", False


def remediate_bootloader_password():
    """
    Remediation for 1.4.1 Ensure bootloader password is set
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for setting bootloader password:{COLORS['RESET']}")
    print("1. Generate a GRUB password hash:")
    print("   sudo grub-mkpasswd-pbkdf2")
    print("   (Enter and confirm your password when prompted)")
    print("2. Create or edit /etc/grub.d/40_custom:")
    print("   sudo nano /etc/grub.d/40_custom")
    print("3. Add the following lines (replace YOUR_PASSWORD_HASH with the hash generated in step 1):")
    print("   set superusers=\"root\"")
    print("   password_pbkdf2 root YOUR_PASSWORD_HASH")
    print("4. Update GRUB configuration:")
    print("   sudo update-grub")
    print("5. Verify the password was added:")
    print("   grep -E '^password|^password_pbkdf2' /boot/grub/grub.cfg")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit bootloader")
    return True


def remediate_bootloader_config_permissions():
    """
    Remediation for 1.4.2 Ensure access to bootloader config is configured
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for securing bootloader config:{COLORS['RESET']}")
    print("1. Set proper ownership:")
    print("   sudo chown root:root /boot/grub/grub.cfg")
    print("2. Set proper permissions:")
    print("   sudo chmod 400 /boot/grub/grub.cfg")
    print("3. Verify the changes:")
    print("   ls -l /boot/grub/grub.cfg")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit bootloader")
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
    password_result = check_bootloader_password()
    results.append(password_result)
    
    permissions_result = check_bootloader_config_permissions()
    results.append(permissions_result)
    
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
    if not remediate_bootloader_password():
        success = False
    
    if not remediate_bootloader_config_permissions():
        success = False
    
    return success