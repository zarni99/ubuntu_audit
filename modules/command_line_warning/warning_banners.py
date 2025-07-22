#!/usr/bin/env python3

"""
CIS Ubuntu 22.04 LTS Benchmark - Section 1.6 Configure Command Line Warning Banners

This module provides functions to audit and optionally remediate the command line
warning banners configuration according to CIS Ubuntu 22.04 LTS Benchmark section 1.6.

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
import re


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


def _check_file_permissions(file_path, expected_permissions):
    """
    Check if a file has the expected permissions
    """
    stdout, _, _ = _run_command(f"stat -c '%a %u %g' {file_path} 2>/dev/null")
    if not stdout:
        return False, f"File {file_path} does not exist"
    
    parts = stdout.split()
    if len(parts) != 3:
        return False, f"Unexpected output from stat command: {stdout}"
    
    actual_perms, owner, group = parts
    
    # Check if permissions match expected
    if actual_perms != expected_permissions:
        return False, f"File {file_path} has permissions {actual_perms}, expected {expected_permissions}"
    
    # Check if owner is root (0)
    if owner != "0":
        return False, f"File {file_path} is owned by UID {owner}, expected 0 (root)"
    
    # Check if group is root (0)
    if group != "0":
        return False, f"File {file_path} has group GID {group}, expected 0 (root)"
    
    return True, ""


def _check_banner_content(file_path):
    """
    Check if a banner file contains appropriate content
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check if content contains any of the restricted strings
        restricted_patterns = [
            r'\bOS\b', r'\bversion\b', r'\brelease\b', r'\bUbuntu\b', 
            r'\bDebian\b', r'\bLinux\b', r'\bkernel\b', r'\bwelcome\b'
        ]
        
        for pattern in restricted_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return False, f"Banner contains restricted information (matching '{pattern}')"
        
        # Check if content is not empty and contains some warning text
        if len(content.strip()) < 20:
            return False, "Banner content is too short or empty"
        
        return True, ""
    except Exception as e:
        return False, f"Error reading banner file: {str(e)}"


def check_message_of_the_day():
    """
    1.6.1 Ensure message of the day is configured properly (Automated)
    """
    benchmark_id = "1.6.1"
    description = "Ensure message of the day is configured properly (Automated)"
    
    # Check if /etc/motd exists and has proper permissions
    motd_exists, _ = _run_command("test -f /etc/motd && echo 'exists' || echo 'not exists'")
    
    if motd_exists == "exists":
        # Check permissions
        perms_ok, perms_msg = _check_file_permissions("/etc/motd", "644")
        
        # Check content
        content_ok, content_msg = _check_banner_content("/etc/motd")
        
        if perms_ok and content_ok:
            print(f"{COLORS['GREEN']}[+] PASS: Message of the day is configured properly{COLORS['RESET']}")
            return True, f"{benchmark_id} {description}", True
        else:
            print(f"{COLORS['RED']}[-] FAIL: Message of the day is not configured properly{COLORS['RESET']}")
            if not perms_ok:
                print(f"    {perms_msg}")
            if not content_ok:
                print(f"    {content_msg}")
            print(f"    Remediation: Configure /etc/motd with proper permissions and content")
            return False, f"{benchmark_id} {description}", False
    else:
        # If /etc/motd doesn't exist, check if the dynamic motd is properly configured
        dynamic_motd, _, _ = _run_command("ls -la /etc/update-motd.d/ 2>/dev/null | wc -l")
        
        if int(dynamic_motd.strip()) > 2:  # More than . and .. entries
            print(f"{COLORS['GREEN']}[+] PASS: Dynamic message of the day is configured{COLORS['RESET']}")
            return True, f"{benchmark_id} {description}", True
        else:
            print(f"{COLORS['RED']}[-] FAIL: Message of the day is not configured{COLORS['RESET']}")
            print(f"    Remediation: Create /etc/motd with proper permissions and content")
            return False, f"{benchmark_id} {description}", False


def check_local_login_warning():
    """
    1.6.2 Ensure local login warning banner is configured properly (Automated)
    """
    benchmark_id = "1.6.2"
    description = "Ensure local login warning banner is configured properly (Automated)"
    
    # Check if /etc/issue exists
    file_exists, _, _ = _run_command("test -f /etc/issue && echo 'exists' || echo 'not exists'")
    
    if file_exists != "exists":
        print(f"{COLORS['RED']}[-] FAIL: Local login warning banner (/etc/issue) does not exist{COLORS['RESET']}")
        print(f"    Remediation: Create /etc/issue with proper permissions and content")
        return False, f"{benchmark_id} {description}", False
    
    # Check permissions
    perms_ok, perms_msg = _check_file_permissions("/etc/issue", "644")
    
    # Check content
    content_ok, content_msg = _check_banner_content("/etc/issue")
    
    if perms_ok and content_ok:
        print(f"{COLORS['GREEN']}[+] PASS: Local login warning banner is configured properly{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    else:
        print(f"{COLORS['RED']}[-] FAIL: Local login warning banner is not configured properly{COLORS['RESET']}")
        if not perms_ok:
            print(f"    {perms_msg}")
        if not content_ok:
            print(f"    {content_msg}")
        print(f"    Remediation: Configure /etc/issue with proper permissions and content")
        return False, f"{benchmark_id} {description}", False


def check_remote_login_warning():
    """
    1.6.3 Ensure remote login warning banner is configured properly (Automated)
    """
    benchmark_id = "1.6.3"
    description = "Ensure remote login warning banner is configured properly (Automated)"
    
    # Check if /etc/issue.net exists
    file_exists, _, _ = _run_command("test -f /etc/issue.net && echo 'exists' || echo 'not exists'")
    
    if file_exists != "exists":
        print(f"{COLORS['RED']}[-] FAIL: Remote login warning banner (/etc/issue.net) does not exist{COLORS['RESET']}")
        print(f"    Remediation: Create /etc/issue.net with proper permissions and content")
        return False, f"{benchmark_id} {description}", False
    
    # Check permissions
    perms_ok, perms_msg = _check_file_permissions("/etc/issue.net", "644")
    
    # Check content
    content_ok, content_msg = _check_banner_content("/etc/issue.net")
    
    if perms_ok and content_ok:
        print(f"{COLORS['GREEN']}[+] PASS: Remote login warning banner is configured properly{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    else:
        print(f"{COLORS['RED']}[-] FAIL: Remote login warning banner is not configured properly{COLORS['RESET']}")
        if not perms_ok:
            print(f"    {perms_msg}")
        if not content_ok:
            print(f"    {content_msg}")
        print(f"    Remediation: Configure /etc/issue.net with proper permissions and content")
        return False, f"{benchmark_id} {description}", False


def check_access_to_etc_issue():
    """
    1.6.4 Ensure access to the su command is restricted (Automated)
    """
    benchmark_id = "1.6.4"
    description = "Ensure access to the su command is restricted (Automated)"
    
    # Check if pam_wheel.so is configured in /etc/pam.d/su
    stdout, _, _ = _run_command("grep pam_wheel.so /etc/pam.d/su")
    
    if "auth required pam_wheel.so use_uid group=sudo" in stdout and not stdout.strip().startswith("#"):
        print(f"{COLORS['GREEN']}[+] PASS: Access to the su command is restricted{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: Access to the su command is not restricted{COLORS['RESET']}")
    print(f"    Current configuration: {stdout if stdout else 'Not configured'}")
    print(f"    Remediation: Configure /etc/pam.d/su to restrict access to the su command")
    return False, f"{benchmark_id} {description}", False


def remediate_message_of_the_day():
    """
    Remediation for 1.6.1 Ensure message of the day is configured properly
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for configuring message of the day:{COLORS['RESET']}")
    print("1. Create or edit /etc/motd with appropriate content:")
    print("   sudo nano /etc/motd")
    print("2. Add a legal warning banner, for example:")
    print("   'Unauthorized access to this system is prohibited. All access and use may be monitored and recorded.'")
    print("3. Ensure the file has proper permissions:")
    print("   sudo chmod 644 /etc/motd")
    print("   sudo chown root:root /etc/motd")
    print("4. Avoid including system information like OS version, kernel version, etc.")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit command_line_warning")
    return True


def remediate_local_login_warning():
    """
    Remediation for 1.6.2 Ensure local login warning banner is configured properly
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for configuring local login warning banner:{COLORS['RESET']}")
    print("1. Create or edit /etc/issue with appropriate content:")
    print("   sudo nano /etc/issue")
    print("2. Add a legal warning banner, for example:")
    print("   'Unauthorized access to this system is prohibited. All access and use may be monitored and recorded.'")
    print("3. Ensure the file has proper permissions:")
    print("   sudo chmod 644 /etc/issue")
    print("   sudo chown root:root /etc/issue")
    print("4. Avoid including system information like OS version, kernel version, etc.")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit command_line_warning")
    return True


def remediate_remote_login_warning():
    """
    Remediation for 1.6.3 Ensure remote login warning banner is configured properly
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for configuring remote login warning banner:{COLORS['RESET']}")
    print("1. Create or edit /etc/issue.net with appropriate content:")
    print("   sudo nano /etc/issue.net")
    print("2. Add a legal warning banner, for example:")
    print("   'Unauthorized access to this system is prohibited. All access and use may be monitored and recorded.'")
    print("3. Ensure the file has proper permissions:")
    print("   sudo chmod 644 /etc/issue.net")
    print("   sudo chown root:root /etc/issue.net")
    print("4. Avoid including system information like OS version, kernel version, etc.")
    print("5. Configure SSH to display the banner by editing /etc/ssh/sshd_config:")
    print("   sudo nano /etc/ssh/sshd_config")
    print("6. Add or modify the line:")
    print("   Banner /etc/issue.net")
    print("7. Restart SSH service:")
    print("   sudo systemctl restart sshd")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit command_line_warning")
    return True


def remediate_access_to_etc_issue():
    """
    Remediation for 1.6.4 Ensure access to the su command is restricted
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for restricting access to the su command:{COLORS['RESET']}")
    print("1. Edit the PAM configuration file for su:")
    print("   sudo nano /etc/pam.d/su")
    print("2. Add or uncomment the following line:")
    print("   auth required pam_wheel.so use_uid group=sudo")
    print("3. Save the file and exit")
    print("4. Verify that only users in the sudo group can use the su command")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit command_line_warning")
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
    motd_result = check_message_of_the_day()
    results.append(motd_result)
    
    local_login_result = check_local_login_warning()
    results.append(local_login_result)
    
    remote_login_result = check_remote_login_warning()
    results.append(remote_login_result)
    
    su_access_result = check_access_to_etc_issue()
    results.append(su_access_result)
    
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
    if not remediate_message_of_the_day():
        success = False
    
    if not remediate_local_login_warning():
        success = False
    
    if not remediate_remote_login_warning():
        success = False
    
    if not remediate_access_to_etc_issue():
        success = False
    
    return success