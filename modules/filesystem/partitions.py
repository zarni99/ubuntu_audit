#!/usr/bin/env python3

"""
CIS Ubuntu 22.04 LTS Benchmark - Section 1.1.2 Filesystem Partitions Audit

This module provides functions to audit and optionally remediate the filesystem
partition configurations according to CIS Ubuntu 22.04 LTS Benchmark section 1.1.2.

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


def _get_mount_info(mount_point):
    """
    Get mount information for a specific mount point
    
    Returns:
        tuple: (is_mounted, mount_options, device)
    """
    stdout, _, _ = _run_command(f"findmnt -n {mount_point}")
    if not stdout:
        return False, [], ""
    
    # Parse the output
    # Example output: /tmp   tmpfs   tmpfs   rw,nosuid,nodev,noexec,relatime
    parts = stdout.split()
    if len(parts) >= 4:
        device = parts[1]
        options = parts[3].split(',')
        return True, options, device
    
    return True, [], ""


def _is_separate_partition(mount_point):
    """
    Check if a mount point is on a separate partition
    """
    is_mounted, _, device = _get_mount_info(mount_point)
    if not is_mounted:
        return False
    
    # Check if it's not the root filesystem
    root_device = ""
    stdout, _, _ = _run_command("findmnt -n /")
    if stdout:
        root_device = stdout.split()[1]
    
    return device != root_device and device != ""


def _has_option(mount_point, option):
    """
    Check if a mount point has a specific option
    """
    is_mounted, options, _ = _get_mount_info(mount_point)
    if not is_mounted:
        return False
    
    return option in options


def check_tmp_partition():
    """
    1.1.2.1 Ensure /tmp is a separate partition
    """
    benchmark_id = "1.1.2.1"
    description = "Ensure /tmp is a separate partition"
    mount_point = "/tmp"
    
    if _is_separate_partition(mount_point):
        print(f"{COLORS['GREEN']}[+] PASS: {mount_point} is mounted on a separate partition{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: {mount_point} is not mounted on a separate partition{COLORS['RESET']}")
    print(f"    Remediation: Create a separate partition for {mount_point} and update /etc/fstab")
    return False, f"{benchmark_id} {description}", False


def check_tmp_nodev():
    """
    1.1.2.2 Ensure nodev option set on /tmp partition
    """
    benchmark_id = "1.1.2.2"
    description = "Ensure nodev option set on /tmp partition"
    mount_point = "/tmp"
    option = "nodev"
    
    if not _is_separate_partition(mount_point):
        print(f"{COLORS['YELLOW']}[!] WARN: {mount_point} is not a separate partition, skipping {option} check{COLORS['RESET']}")
        return False, f"{benchmark_id} {description}", False
    
    if _has_option(mount_point, option):
        print(f"{COLORS['GREEN']}[+] PASS: {option} option is set on {mount_point}{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: {option} option is not set on {mount_point}{COLORS['RESET']}")
    print(f"    Remediation: Add the {option} option to the {mount_point} entry in /etc/fstab")
    return False, f"{benchmark_id} {description}", False


def check_tmp_nosuid():
    """
    1.1.2.3 Ensure nosuid option set on /tmp partition
    """
    benchmark_id = "1.1.2.3"
    description = "Ensure nosuid option set on /tmp partition"
    mount_point = "/tmp"
    option = "nosuid"
    
    if not _is_separate_partition(mount_point):
        print(f"{COLORS['YELLOW']}[!] WARN: {mount_point} is not a separate partition, skipping {option} check{COLORS['RESET']}")
        return False, f"{benchmark_id} {description}", False
    
    if _has_option(mount_point, option):
        print(f"{COLORS['GREEN']}[+] PASS: {option} option is set on {mount_point}{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: {option} option is not set on {mount_point}{COLORS['RESET']}")
    print(f"    Remediation: Add the {option} option to the {mount_point} entry in /etc/fstab")
    return False, f"{benchmark_id} {description}", False


def check_tmp_noexec():
    """
    1.1.2.4 Ensure noexec option set on /tmp partition
    """
    benchmark_id = "1.1.2.4"
    description = "Ensure noexec option set on /tmp partition"
    mount_point = "/tmp"
    option = "noexec"
    
    if not _is_separate_partition(mount_point):
        print(f"{COLORS['YELLOW']}[!] WARN: {mount_point} is not a separate partition, skipping {option} check{COLORS['RESET']}")
        return False, f"{benchmark_id} {description}", False
    
    if _has_option(mount_point, option):
        print(f"{COLORS['GREEN']}[+] PASS: {option} option is set on {mount_point}{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: {option} option is not set on {mount_point}{COLORS['RESET']}")
    print(f"    Remediation: Add the {option} option to the {mount_point} entry in /etc/fstab")
    return False, f"{benchmark_id} {description}", False


def check_dev_shm_partition():
    """
    1.1.2.5 Ensure /dev/shm is a separate partition
    """
    benchmark_id = "1.1.2.5"
    description = "Ensure /dev/shm is configured"
    mount_point = "/dev/shm"
    
    is_mounted, _, _ = _get_mount_info(mount_point)
    if is_mounted:
        print(f"{COLORS['GREEN']}[+] PASS: {mount_point} is properly configured{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: {mount_point} is not properly configured{COLORS['RESET']}")
    print(f"    Remediation: Ensure {mount_point} is properly mounted")
    return False, f"{benchmark_id} {description}", False


def check_dev_shm_nodev():
    """
    1.1.2.6 Ensure nodev option set on /dev/shm partition
    """
    benchmark_id = "1.1.2.6"
    description = "Ensure nodev option set on /dev/shm partition"
    mount_point = "/dev/shm"
    option = "nodev"
    
    is_mounted, _, _ = _get_mount_info(mount_point)
    if not is_mounted:
        print(f"{COLORS['YELLOW']}[!] WARN: {mount_point} is not properly configured, skipping {option} check{COLORS['RESET']}")
        return False, f"{benchmark_id} {description}", False
    
    if _has_option(mount_point, option):
        print(f"{COLORS['GREEN']}[+] PASS: {option} option is set on {mount_point}{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: {option} option is not set on {mount_point}{COLORS['RESET']}")
    print(f"    Remediation: Add the {option} option to the {mount_point} entry in /etc/fstab")
    return False, f"{benchmark_id} {description}", False


def check_dev_shm_nosuid():
    """
    1.1.2.7 Ensure nosuid option set on /dev/shm partition
    """
    benchmark_id = "1.1.2.7"
    description = "Ensure nosuid option set on /dev/shm partition"
    mount_point = "/dev/shm"
    option = "nosuid"
    
    is_mounted, _, _ = _get_mount_info(mount_point)
    if not is_mounted:
        print(f"{COLORS['YELLOW']}[!] WARN: {mount_point} is not properly configured, skipping {option} check{COLORS['RESET']}")
        return False, f"{benchmark_id} {description}", False
    
    if _has_option(mount_point, option):
        print(f"{COLORS['GREEN']}[+] PASS: {option} option is set on {mount_point}{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: {option} option is not set on {mount_point}{COLORS['RESET']}")
    print(f"    Remediation: Add the {option} option to the {mount_point} entry in /etc/fstab")
    return False, f"{benchmark_id} {description}", False


def check_dev_shm_noexec():
    """
    1.1.2.8 Ensure noexec option set on /dev/shm partition
    """
    benchmark_id = "1.1.2.8"
    description = "Ensure noexec option set on /dev/shm partition"
    mount_point = "/dev/shm"
    option = "noexec"
    
    is_mounted, _, _ = _get_mount_info(mount_point)
    if not is_mounted:
        print(f"{COLORS['YELLOW']}[!] WARN: {mount_point} is not properly configured, skipping {option} check{COLORS['RESET']}")
        return False, f"{benchmark_id} {description}", False
    
    if _has_option(mount_point, option):
        print(f"{COLORS['GREEN']}[+] PASS: {option} option is set on {mount_point}{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: {option} option is not set on {mount_point}{COLORS['RESET']}")
    print(f"    Remediation: Add the {option} option to the {mount_point} entry in /etc/fstab")
    return False, f"{benchmark_id} {description}", False


# Removed individual remediation functions as they are no longer needed.
# All remediation suggestions are now provided in the run_all_remediations function.


def run_all_audits(return_results=False):
    """
    Run all filesystem partition audit checks
    
    Args:
        return_results: If True, return a list of results instead of just True/False
    
    Returns:
        If return_results is True, returns a list of tuples (benchmark_id_description, result)
        Otherwise, returns True if all checks pass, False otherwise
    """
    print(f"{COLORS['BLUE']}Running Filesystem Partition Configuration Audits...{COLORS['RESET']}")
    
    results = [
        check_tmp_partition(),
        check_tmp_nodev(),
        check_tmp_nosuid(),
        check_tmp_noexec(),
        check_dev_shm_partition(),
        check_dev_shm_nodev(),
        check_dev_shm_nosuid(),
        check_dev_shm_noexec()
    ]
    
    # Count passes and fails
    passes = sum(1 for result in results if result[0])
    fails = len(results) - passes
    
    print("\n" + "-" * 60)
    print(f"{COLORS['BLUE']}Filesystem Partition Configuration Audit Summary:{COLORS['RESET']}")
    print(f"{COLORS['GREEN']}PASS: {passes}{COLORS['RESET']}")
    print(f"{COLORS['RED']}FAIL: {fails}{COLORS['RESET']}")
    print("-" * 60)
    
    if return_results:
        # Return a list of tuples (benchmark_id_description, result)
        return [(result[1], result[2]) for result in results]
    
    return all(result[0] for result in results)


def run_all_remediations():
    """
    Display manual remediation instructions for all filesystem partition checks
    """
    print(f"{COLORS['BLUE']}Filesystem Partition Configuration Remediation Guide{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}NOTE: All filesystem partition remediations require manual intervention.{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}The following are suggestions for how to remediate each issue.{COLORS['RESET']}\n")
    
    # 1.1.2.1 /tmp partition
    print(f"{COLORS['BLUE']}1.1.2.1 Ensure /tmp is a separate partition{COLORS['RESET']}")
    print("Manual remediation steps:")
    print("    1. Back up any data in /tmp")
    print("    2. Create a new partition or logical volume for /tmp")
    print("    3. Add an entry to /etc/fstab similar to:")
    print("       UUID=<UUID> /tmp ext4 defaults,nodev,nosuid,noexec 0 2")
    print("    4. Mount the new partition: mount /tmp")
    print("    5. Restore any data to /tmp if needed\n")
    
    # 1.1.2.2 /tmp nodev
    print(f"{COLORS['BLUE']}1.1.2.2 Ensure nodev option set on /tmp partition{COLORS['RESET']}")
    print("Manual remediation steps:")
    print("    1. Edit /etc/fstab and add the nodev option to the /tmp entry")
    print("    2. Remount /tmp: mount -o remount /tmp\n")
    
    # 1.1.2.3 /tmp nosuid
    print(f"{COLORS['BLUE']}1.1.2.3 Ensure nosuid option set on /tmp partition{COLORS['RESET']}")
    print("Manual remediation steps:")
    print("    1. Edit /etc/fstab and add the nosuid option to the /tmp entry")
    print("    2. Remount /tmp: mount -o remount /tmp\n")
    
    # 1.1.2.4 /tmp noexec
    print(f"{COLORS['BLUE']}1.1.2.4 Ensure noexec option set on /tmp partition{COLORS['RESET']}")
    print("Manual remediation steps:")
    print("    1. Edit /etc/fstab and add the noexec option to the /tmp entry")
    print("    2. Remount /tmp: mount -o remount /tmp\n")
    
    # 1.1.2.5 /dev/shm partition
    print(f"{COLORS['BLUE']}1.1.2.5 Ensure /dev/shm is configured{COLORS['RESET']}")
    print("Manual remediation steps:")
    print("    1. Edit /etc/fstab and add an entry for /dev/shm:")
    print("       tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0")
    print("    2. Mount /dev/shm: mount /dev/shm\n")
    
    # 1.1.2.6 /dev/shm nodev
    print(f"{COLORS['BLUE']}1.1.2.6 Ensure nodev option set on /dev/shm partition{COLORS['RESET']}")
    print("Manual remediation steps:")
    print("    1. Edit /etc/fstab and add the nodev option to the /dev/shm entry")
    print("    2. Remount /dev/shm: mount -o remount /dev/shm\n")
    
    # 1.1.2.7 /dev/shm nosuid
    print(f"{COLORS['BLUE']}1.1.2.7 Ensure nosuid option set on /dev/shm partition{COLORS['RESET']}")
    print("Manual remediation steps:")
    print("    1. Edit /etc/fstab and add the nosuid option to the /dev/shm entry")
    print("    2. Remount /dev/shm: mount -o remount /dev/shm\n")
    
    # 1.1.2.8 /dev/shm noexec
    print(f"{COLORS['BLUE']}1.1.2.8 Ensure noexec option set on /dev/shm partition{COLORS['RESET']}")
    print("Manual remediation steps:")
    print("    1. Edit /etc/fstab and add the noexec option to the /dev/shm entry")
    print("    2. Remount /dev/shm: mount -o remount /dev/shm\n")
    
    print(f"{COLORS['YELLOW']}After making these changes, run the audit again to verify:{COLORS['RESET']}")
    print("    python3 cis_audit.py audit filesystem --user-friendly")
    
    return False  # Always return False as these remediations require manual intervention


def main():
    """
    Main function to parse arguments and run appropriate functions
    """
    if len(sys.argv) < 2:
        print("Error: Missing required argument.")
        print("Usage: python3 partitions.py [audit|remediate]")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    
    if mode == "audit":
        success = run_all_audits()
        sys.exit(0 if success else 1)
    elif mode == "remediate":
        success = run_all_remediations()
        sys.exit(0 if success else 1)
    else:
        print(f"Error: Invalid mode '{mode}'.")
        print("Usage: python3 partitions.py [audit|remediate]")
        sys.exit(1)


if __name__ == "__main__":
    main()