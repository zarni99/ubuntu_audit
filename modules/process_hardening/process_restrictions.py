#!/usr/bin/env python3

"""
CIS Ubuntu 22.04 LTS Benchmark - Section 1.5 Configure Additional Process Hardening

This module provides functions to audit and optionally remediate the process
hardening configuration according to CIS Ubuntu 22.04 LTS Benchmark section 1.5.

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


def check_address_space_layout_randomization():
    """
    1.5.1 Ensure address space layout randomization (ASLR) is enabled (Automated)
    """
    benchmark_id = "1.5.1"
    description = "Ensure address space layout randomization (ASLR) is enabled (Automated)"
    
    # Check if ASLR is enabled
    stdout, _, _ = _run_command("sysctl kernel.randomize_va_space")
    
    if "kernel.randomize_va_space = 2" in stdout:
        print(f"{COLORS['GREEN']}[+] PASS: Address space layout randomization (ASLR) is enabled{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: Address space layout randomization (ASLR) is not properly enabled{COLORS['RESET']}")
    print(f"    Current setting: {stdout}")
    print(f"    Remediation: Set kernel.randomize_va_space to 2")
    return False, f"{benchmark_id} {description}", False


def check_ptrace_scope():
    """
    1.5.2 Ensure ptrace scope is restricted (Automated)
    """
    benchmark_id = "1.5.2"
    description = "Ensure ptrace scope is restricted (Automated)"
    
    # Check if ptrace scope is restricted
    stdout, _, _ = _run_command("sysctl kernel.yama.ptrace_scope")
    
    if "kernel.yama.ptrace_scope = 1" in stdout or "kernel.yama.ptrace_scope = 2" in stdout or "kernel.yama.ptrace_scope = 3" in stdout:
        print(f"{COLORS['GREEN']}[+] PASS: ptrace scope is restricted{COLORS['RESET']}")
        print(f"    Current setting: {stdout}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: ptrace scope is not restricted{COLORS['RESET']}")
    print(f"    Current setting: {stdout}")
    print(f"    Remediation: Set kernel.yama.ptrace_scope to at least 1")
    return False, f"{benchmark_id} {description}", False


def check_core_dumps_restricted():
    """
    1.5.3 Ensure core dumps are restricted (Automated)
    """
    benchmark_id = "1.5.3"
    description = "Ensure core dumps are restricted (Automated)"
    
    # Check if core dumps are restricted in sysctl
    sysctl_stdout, _, _ = _run_command("sysctl fs.suid_dumpable")
    
    # Check if core dumps are restricted in limits.conf
    limits_stdout, _, _ = _run_command("grep -E \"hard core\" /etc/security/limits.conf /etc/security/limits.d/*")
    
    # Check if systemd-coredump is configured properly
    systemd_stdout, _, _ = _run_command("systemctl is-enabled coredump.service 2>/dev/null || echo 'not installed'")
    
    if "fs.suid_dumpable = 0" in sysctl_stdout and "hard core 0" in limits_stdout:
        print(f"{COLORS['GREEN']}[+] PASS: Core dumps are restricted{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: Core dumps are not properly restricted{COLORS['RESET']}")
    print(f"    sysctl setting: {sysctl_stdout}")
    print(f"    limits.conf setting: {'Properly configured' if 'hard core 0' in limits_stdout else 'Not properly configured'}")
    print(f"    Remediation: Set fs.suid_dumpable to 0 and add 'hard core 0' to limits.conf")
    return False, f"{benchmark_id} {description}", False


def check_prelink_not_installed():
    """
    1.5.4 Ensure prelink is not installed (Automated)
    """
    benchmark_id = "1.5.4"
    description = "Ensure prelink is not installed (Automated)"
    
    # Check if prelink is installed
    stdout, _, _ = _run_command("dpkg -s prelink 2>/dev/null | grep -E '^Status: install'")
    
    if not stdout:
        print(f"{COLORS['GREEN']}[+] PASS: prelink is not installed{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: prelink is installed{COLORS['RESET']}")
    print(f"    Remediation: Run 'sudo apt purge prelink' to remove prelink")
    return False, f"{benchmark_id} {description}", False


def check_automatic_error_reporting():
    """
    1.5.5 Ensure Automatic Error Reporting is not enabled (Automated)
    """
    benchmark_id = "1.5.5"
    description = "Ensure Automatic Error Reporting is not enabled (Automated)"
    
    # Check if apport service is enabled
    stdout, _, _ = _run_command("systemctl is-enabled apport.service 2>/dev/null || echo 'not installed'")
    
    if stdout == "disabled" or stdout == "not installed":
        print(f"{COLORS['GREEN']}[+] PASS: Automatic Error Reporting is not enabled{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: Automatic Error Reporting is enabled{COLORS['RESET']}")
    print(f"    Current status: {stdout}")
    print(f"    Remediation: Run 'sudo systemctl disable apport.service' to disable automatic error reporting")
    return False, f"{benchmark_id} {description}", False


def remediate_address_space_layout_randomization():
    """
    Remediation for 1.5.1 Ensure address space layout randomization (ASLR) is enabled
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for enabling ASLR:{COLORS['RESET']}")
    print("1. Set the runtime value:")
    print("   sudo sysctl -w kernel.randomize_va_space=2")
    print("2. Make the setting persistent:")
    print("   echo 'kernel.randomize_va_space = 2' | sudo tee /etc/sysctl.d/60-kernel-randomize_va_space.conf")
    print("3. Apply the settings:")
    print("   sudo sysctl -p /etc/sysctl.d/60-kernel-randomize_va_space.conf")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit process_hardening")
    return True


def remediate_ptrace_scope():
    """
    Remediation for 1.5.2 Ensure ptrace scope is restricted
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for restricting ptrace scope:{COLORS['RESET']}")
    print("1. Set the runtime value:")
    print("   sudo sysctl -w kernel.yama.ptrace_scope=1")
    print("2. Make the setting persistent:")
    print("   echo 'kernel.yama.ptrace_scope = 1' | sudo tee /etc/sysctl.d/10-ptrace.conf")
    print("3. Apply the settings:")
    print("   sudo sysctl -p /etc/sysctl.d/10-ptrace.conf")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit process_hardening")
    return True


def remediate_core_dumps_restricted():
    """
    Remediation for 1.5.3 Ensure core dumps are restricted
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for restricting core dumps:{COLORS['RESET']}")
    print("1. Set the runtime sysctl value:")
    print("   sudo sysctl -w fs.suid_dumpable=0")
    print("2. Make the sysctl setting persistent:")
    print("   echo 'fs.suid_dumpable = 0' | sudo tee /etc/sysctl.d/50-coredump.conf")
    print("3. Apply the sysctl settings:")
    print("   sudo sysctl -p /etc/sysctl.d/50-coredump.conf")
    print("4. Set hard limit for core dumps:")
    print("   echo '* hard core 0' | sudo tee -a /etc/security/limits.conf")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit process_hardening")
    return True


def remediate_prelink_not_installed():
    """
    Remediation for 1.5.4 Ensure prelink is not installed
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for removing prelink:{COLORS['RESET']}")
    print("1. If prelink is installed, first restore the system:")
    print("   sudo prelink -ua")
    print("2. Remove the prelink package:")
    print("   sudo apt purge prelink")
    print("3. Verify prelink is removed:")
    print("   dpkg -s prelink")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit process_hardening")
    return True


def remediate_automatic_error_reporting():
    """
    Remediation for 1.5.5 Ensure Automatic Error Reporting is not enabled
    """
    print(f"{COLORS['YELLOW']}Manual remediation steps for disabling Automatic Error Reporting:{COLORS['RESET']}")
    print("1. Disable the apport service:")
    print("   sudo systemctl disable apport.service")
    print("   sudo systemctl stop apport.service")
    print("2. Edit the apport configuration file:")
    print("   sudo nano /etc/default/apport")
    print("3. Set enabled=0 in the configuration file")
    print("4. Verify the service is disabled:")
    print("   systemctl is-enabled apport.service")
    
    print(f"\n{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print(f"sudo python3 cis_audit.py audit process_hardening")
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
    aslr_result = check_address_space_layout_randomization()
    results.append(aslr_result)
    
    ptrace_result = check_ptrace_scope()
    results.append(ptrace_result)
    
    core_dumps_result = check_core_dumps_restricted()
    results.append(core_dumps_result)
    
    prelink_result = check_prelink_not_installed()
    results.append(prelink_result)
    
    error_reporting_result = check_automatic_error_reporting()
    results.append(error_reporting_result)
    
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
    if not remediate_address_space_layout_randomization():
        success = False
    
    if not remediate_ptrace_scope():
        success = False
    
    if not remediate_core_dumps_restricted():
        success = False
    
    if not remediate_prelink_not_installed():
        success = False
    
    if not remediate_automatic_error_reporting():
        success = False
    
    return success