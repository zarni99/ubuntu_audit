#!/usr/bin/env python3

"""
CIS Ubuntu 22.04 LTS Benchmark - Section 1.1.1 Filesystem Kernel Modules Audit

This module provides functions to audit and optionally remediate the filesystem
kernel modules according to CIS Ubuntu 22.04 LTS Benchmark section 1.1.1.

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


def _is_module_loaded(module_name):
    """
    Check if a kernel module is loaded
    """
    stdout, _, _ = _run_command(f"lsmod | grep {module_name}")
    return bool(stdout)


def _is_module_available(module_name):
    """
    Check if a kernel module is available to be loaded
    """
    stdout, _, _ = _run_command(f"modprobe -n -v {module_name}")
    return not ("not found" in stdout or "No such file or directory" in stdout)


def _is_module_disabled(module_name):
    """
    Check if a kernel module is disabled via modprobe config
    """
    stdout, _, _ = _run_command(f"modprobe -n -v {module_name}")
    return "install /bin/true" in stdout or "install /bin/false" in stdout


def _disable_module(module_name):
    """
    Disable a kernel module by creating a .conf file in /etc/modprobe.d/
    """
    conf_file = f"/etc/modprobe.d/disable-{module_name}.conf"
    command = f"echo 'install {module_name} /bin/true' > {conf_file}"
    stdout, stderr, rc = _run_command(command)
    return rc == 0


def check_cramfs():
    """
    1.1.1.1 Ensure cramfs kernel module is not available
    """
    module_name = "cramfs"
    benchmark_id = "1.1.1.1"
    description = f"Ensure {module_name} kernel module is not available"
    
    if _is_module_loaded(module_name):
        print(f"{COLORS['RED']}[-] FAIL: {module_name} module is loaded{COLORS['RESET']}")
        print(f"    Remediation: Run 'rmmod {module_name}' to unload the module")
        return False, f"{benchmark_id} {description}", False
    
    if not _is_module_available(module_name) or _is_module_disabled(module_name):
        print(f"{COLORS['GREEN']}[+] PASS: {module_name} module is not available or is disabled{COLORS['RESET']}")
        return True, f"{benchmark_id} {description}", True
    
    print(f"{COLORS['RED']}[-] FAIL: {module_name} module is available to be loaded{COLORS['RESET']}")
    print(f"    Remediation: Run 'sudo modprobe -r {module_name}' and create a disable-{module_name}.conf file")
    return False, f"{benchmark_id} {description}", False


def remediate_cramfs():
    """
    Remediate 1.1.1.1 Ensure cramfs kernel module is not available
    """
    module_name = "cramfs"
    print(f"{COLORS['BLUE']}Remediating: 1.1.1.1 Ensure {module_name} kernel module is not available{COLORS['RESET']}")
    
    print(f"{COLORS['YELLOW']}Manual remediation steps:{COLORS['RESET']}")
    print(f"    1. Unload the module if it's loaded: sudo modprobe -r {module_name}")
    print(f"    2. Create a configuration file to disable the module:")
    print(f"       sudo echo 'install {module_name} /bin/true' > /etc/modprobe.d/disable-{module_name}.conf")
    print(f"    3. Update the initramfs: sudo update-initramfs -u")
    
    return True


def check_freevxfs():
    """
    1.1.1.2 Ensure freevxfs kernel module is not available
    """
    module_name = "freevxfs"
    
    if _is_module_loaded(module_name):
        print(f"{COLORS['RED']}[-] FAIL: {module_name} module is loaded{COLORS['RESET']}")
        print(f"    Remediation: Run 'rmmod {module_name}' to unload the module")
        return False, f"1.1.1.2 Ensure {module_name} kernel module is not available", False
    
    if not _is_module_available(module_name) or _is_module_disabled(module_name):
        print(f"{COLORS['GREEN']}[+] PASS: {module_name} module is not available or is disabled{COLORS['RESET']}")
        return True, f"1.1.1.2 Ensure {module_name} kernel module is not available", True
    
    print(f"{COLORS['RED']}[-] FAIL: {module_name} module is available to be loaded{COLORS['RESET']}")
    print(f"    Remediation: Run 'sudo modprobe -r {module_name}' and create a disable-{module_name}.conf file")
    return False, f"1.1.1.2 Ensure {module_name} kernel module is not available", False


def remediate_freevxfs():
    """
    Remediate 1.1.1.2 Ensure freevxfs kernel module is not available
    """
    module_name = "freevxfs"
    print(f"{COLORS['BLUE']}Remediating: 1.1.1.2 Ensure {module_name} kernel module is not available{COLORS['RESET']}")
    
    print(f"{COLORS['YELLOW']}Manual remediation steps:{COLORS['RESET']}")
    print(f"    1. Unload the module if it's loaded: sudo modprobe -r {module_name}")
    print(f"    2. Create a configuration file to disable the module:")
    print(f"       sudo echo 'install {module_name} /bin/true' > /etc/modprobe.d/disable-{module_name}.conf")
    print(f"    3. Update the initramfs: sudo update-initramfs -u")
    
    return True


def check_jffs2():
    """
    1.1.1.3 Ensure jffs2 kernel module is not available
    """
    module_name = "jffs2"
    
    if _is_module_loaded(module_name):
        print(f"{COLORS['RED']}[-] FAIL: {module_name} module is loaded{COLORS['RESET']}")
        print(f"    Remediation: Run 'rmmod {module_name}' to unload the module")
        return False, f"1.1.1.3 Ensure {module_name} kernel module is not available", False
    
    if not _is_module_available(module_name) or _is_module_disabled(module_name):
        print(f"{COLORS['GREEN']}[+] PASS: {module_name} module is not available or is disabled{COLORS['RESET']}")
        return True, f"1.1.1.3 Ensure {module_name} kernel module is not available", True
    
    print(f"{COLORS['RED']}[-] FAIL: {module_name} module is available to be loaded{COLORS['RESET']}")
    print(f"    Remediation: Run 'sudo modprobe -r {module_name}' and create a disable-{module_name}.conf file")
    return False, f"1.1.1.3 Ensure {module_name} kernel module is not available", False


def remediate_jffs2():
    """
    Remediate 1.1.1.3 Ensure jffs2 kernel module is not available
    """
    module_name = "jffs2"
    print(f"{COLORS['BLUE']}Remediating: 1.1.1.3 Ensure {module_name} kernel module is not available{COLORS['RESET']}")
    
    print(f"{COLORS['YELLOW']}Manual remediation steps:{COLORS['RESET']}")
    print(f"    1. Unload the module if it's loaded: sudo modprobe -r {module_name}")
    print(f"    2. Create a configuration file to disable the module:")
    print(f"       sudo echo 'install {module_name} /bin/true' > /etc/modprobe.d/disable-{module_name}.conf")
    print(f"    3. Update the initramfs: sudo update-initramfs -u")
    
    return True


def check_hfs():
    """
    1.1.1.4 Ensure hfs kernel module is not available
    """
    module_name = "hfs"
    
    if _is_module_loaded(module_name):
        print(f"{COLORS['RED']}[-] FAIL: {module_name} module is loaded{COLORS['RESET']}")
        print(f"    Remediation: Run 'rmmod {module_name}' to unload the module")
        return False, f"1.1.1.4 Ensure {module_name} kernel module is not available", False
    
    if not _is_module_available(module_name) or _is_module_disabled(module_name):
        print(f"{COLORS['GREEN']}[+] PASS: {module_name} module is not available or is disabled{COLORS['RESET']}")
        return True, f"1.1.1.4 Ensure {module_name} kernel module is not available", True
    
    print(f"{COLORS['RED']}[-] FAIL: {module_name} module is available to be loaded{COLORS['RESET']}")
    print(f"    Remediation: Run 'sudo modprobe -r {module_name}' and create a disable-{module_name}.conf file")
    return False, f"1.1.1.4 Ensure {module_name} kernel module is not available", False


def remediate_hfs():
    """
    Remediate 1.1.1.4 Ensure hfs kernel module is not available
    """
    module_name = "hfs"
    print(f"{COLORS['BLUE']}Remediating: 1.1.1.4 Ensure {module_name} kernel module is not available{COLORS['RESET']}")
    
    print(f"{COLORS['YELLOW']}Manual remediation steps:{COLORS['RESET']}")
    print(f"    1. Unload the module if it's loaded: sudo modprobe -r {module_name}")
    print(f"    2. Create a configuration file to disable the module:")
    print(f"       sudo echo 'install {module_name} /bin/true' > /etc/modprobe.d/disable-{module_name}.conf")
    print(f"    3. Update the initramfs: sudo update-initramfs -u")
    
    return True


def check_hfsplus():
    """
    1.1.1.5 Ensure hfsplus kernel module is not available
    """
    module_name = "hfsplus"
    
    if _is_module_loaded(module_name):
        print(f"{COLORS['RED']}[-] FAIL: {module_name} module is loaded{COLORS['RESET']}")
        print(f"    Remediation: Run 'rmmod {module_name}' to unload the module")
        return False, f"1.1.1.5 Ensure {module_name} kernel module is not available", False
    
    if not _is_module_available(module_name) or _is_module_disabled(module_name):
        print(f"{COLORS['GREEN']}[+] PASS: {module_name} module is not available or is disabled{COLORS['RESET']}")
        return True, f"1.1.1.5 Ensure {module_name} kernel module is not available", True
    
    print(f"{COLORS['RED']}[-] FAIL: {module_name} module is available to be loaded{COLORS['RESET']}")
    print(f"    Remediation: Run 'sudo modprobe -r {module_name}' and create a disable-{module_name}.conf file")
    return False, f"1.1.1.5 Ensure {module_name} kernel module is not available", False


def remediate_hfsplus():
    """
    Remediate 1.1.1.5 Ensure hfsplus kernel module is not available
    """
    module_name = "hfsplus"
    print(f"{COLORS['BLUE']}Remediating: 1.1.1.5 Ensure {module_name} kernel module is not available{COLORS['RESET']}")
    
    print(f"{COLORS['YELLOW']}Manual remediation steps:{COLORS['RESET']}")
    print(f"    1. Unload the module if it's loaded: sudo modprobe -r {module_name}")
    print(f"    2. Create a configuration file to disable the module:")
    print(f"       sudo echo 'install {module_name} /bin/true' > /etc/modprobe.d/disable-{module_name}.conf")
    print(f"    3. Update the initramfs: sudo update-initramfs -u")
    
    return True


def check_squashfs():
    """
    1.1.1.6 Ensure squashfs kernel module is not available
    """
    module_name = "squashfs"
    
    if _is_module_loaded(module_name):
        print(f"{COLORS['RED']}[-] FAIL: {module_name} module is loaded{COLORS['RESET']}")
        print(f"    Remediation: Run 'rmmod {module_name}' to unload the module")
        return False, f"1.1.1.6 Ensure {module_name} kernel module is not available", False
    
    if not _is_module_available(module_name) or _is_module_disabled(module_name):
        print(f"{COLORS['GREEN']}[+] PASS: {module_name} module is not available or is disabled{COLORS['RESET']}")
        return True, f"1.1.1.6 Ensure {module_name} kernel module is not available", True
    
    print(f"{COLORS['RED']}[-] FAIL: {module_name} module is available to be loaded{COLORS['RESET']}")
    print(f"    Remediation: Run 'sudo modprobe -r {module_name}' and create a disable-{module_name}.conf file")
    return False, f"1.1.1.6 Ensure {module_name} kernel module is not available", False


def remediate_squashfs():
    """
    Remediate 1.1.1.6 Ensure squashfs kernel module is not available
    """
    module_name = "squashfs"
    print(f"{COLORS['BLUE']}Remediating: 1.1.1.6 Ensure {module_name} kernel module is not available{COLORS['RESET']}")
    
    print(f"{COLORS['YELLOW']}Manual remediation steps:{COLORS['RESET']}")
    print(f"    1. Unload the module if it's loaded: sudo modprobe -r {module_name}")
    print(f"    2. Create a configuration file to disable the module:")
    print(f"       sudo echo 'install {module_name} /bin/true' > /etc/modprobe.d/disable-{module_name}.conf")
    print(f"    3. Update the initramfs: sudo update-initramfs -u")
    
    return True


def check_udf():
    """
    1.1.1.7 Ensure udf kernel module is not available
    """
    module_name = "udf"
    
    if _is_module_loaded(module_name):
        print(f"{COLORS['RED']}[-] FAIL: {module_name} module is loaded{COLORS['RESET']}")
        print(f"    Remediation: Run 'rmmod {module_name}' to unload the module")
        return False, f"1.1.1.7 Ensure {module_name} kernel module is not available", False
    
    if not _is_module_available(module_name) or _is_module_disabled(module_name):
        print(f"{COLORS['GREEN']}[+] PASS: {module_name} module is not available or is disabled{COLORS['RESET']}")
        return True, f"1.1.1.7 Ensure {module_name} kernel module is not available", True
    
    print(f"{COLORS['RED']}[-] FAIL: {module_name} module is available to be loaded{COLORS['RESET']}")
    print(f"    Remediation: Run 'sudo modprobe -r {module_name}' and create a disable-{module_name}.conf file")
    return False, f"1.1.1.7 Ensure {module_name} kernel module is not available", False


def remediate_udf():
    """
    Remediate 1.1.1.7 Ensure udf kernel module is not available
    """
    module_name = "udf"
    print(f"{COLORS['BLUE']}Remediating: 1.1.1.7 Ensure {module_name} kernel module is not available{COLORS['RESET']}")
    
    print(f"{COLORS['YELLOW']}Manual remediation steps:{COLORS['RESET']}")
    print(f"    1. Unload the module if it's loaded: sudo modprobe -r {module_name}")
    print(f"    2. Create a configuration file to disable the module:")
    print(f"       sudo echo 'install {module_name} /bin/true' > /etc/modprobe.d/disable-{module_name}.conf")
    print(f"    3. Update the initramfs: sudo update-initramfs -u")
    
    return True


def check_fat():
    """
    1.1.1.8 Ensure FAT kernel module is not available
    """
    # Check for both fat and vfat modules
    fat_result = True
    vfat_result = True
    
    # Check fat module
    if _is_module_loaded("fat"):
        print(f"{COLORS['RED']}[-] FAIL: fat module is loaded{COLORS['RESET']}")
        print("    Remediation: Run 'rmmod fat' to unload the module")
        fat_result = False
    elif not _is_module_available("fat") or _is_module_disabled("fat"):
        print(f"{COLORS['GREEN']}[+] PASS: fat module is not available or is disabled{COLORS['RESET']}")
    else:
        print(f"{COLORS['RED']}[-] FAIL: fat module is available to be loaded{COLORS['RESET']}")
        print("    Remediation: Run 'sudo modprobe -r fat' and create a disable-fat.conf file")
        fat_result = False
    
    # Check vfat module
    if _is_module_loaded("vfat"):
        print(f"{COLORS['RED']}[-] FAIL: vfat module is loaded{COLORS['RESET']}")
        print("    Remediation: Run 'rmmod vfat' to unload the module")
        vfat_result = False
    elif not _is_module_available("vfat") or _is_module_disabled("vfat"):
        print(f"{COLORS['GREEN']}[+] PASS: vfat module is not available or is disabled{COLORS['RESET']}")
    else:
        print(f"{COLORS['RED']}[-] FAIL: vfat module is available to be loaded{COLORS['RESET']}")
        print("    Remediation: Run 'sudo modprobe -r vfat' and create a disable-vfat.conf file")
        vfat_result = False
    
    overall_result = fat_result and vfat_result
    return overall_result, "1.1.1.8 Ensure FAT kernel module is not available", overall_result


def remediate_fat():
    """
    Remediate 1.1.1.8 Ensure FAT kernel module is not available
    """
    print(f"{COLORS['BLUE']}Remediating: 1.1.1.8 Ensure FAT kernel module is not available{COLORS['RESET']}")
    
    print(f"{COLORS['YELLOW']}Manual remediation steps:{COLORS['RESET']}")
    print("    1. Unload the vfat module first (as it depends on fat): sudo modprobe -r vfat")
    print("    2. Create a configuration file to disable the vfat module:")
    print("       sudo echo 'install vfat /bin/true' > /etc/modprobe.d/disable-vfat.conf")
    print("    3. Unload the fat module: sudo modprobe -r fat")
    print("    4. Create a configuration file to disable the fat module:")
    print("       sudo echo 'install fat /bin/true' > /etc/modprobe.d/disable-fat.conf")
    print("    5. Update the initramfs: sudo update-initramfs -u")
    
    return True


def run_all_audits(return_results=False):
    """
    Run all filesystem kernel module audit checks
    
    Args:
        return_results: If True, return a list of results instead of just True/False
    
    Returns:
        If return_results is True, returns a list of tuples (benchmark_id, description, result)
        Otherwise, returns True if all checks pass, False otherwise
    """
    print(f"{COLORS['BLUE']}Running Filesystem Kernel Module Audits...{COLORS['RESET']}")
    
    results = [
        check_cramfs(),
        check_freevxfs(),
        check_jffs2(),
        check_hfs(),
        check_hfsplus(),
        check_squashfs(),
        check_udf(),
        check_fat()
    ]
    
    # Count passes and fails
    passes = sum(1 for result in results if result[0])
    fails = len(results) - passes
    
    print("\n" + "-" * 60)
    print(f"{COLORS['BLUE']}Filesystem Kernel Module Audit Summary:{COLORS['RESET']}")
    print(f"{COLORS['GREEN']}PASS: {passes}{COLORS['RESET']}")
    print(f"{COLORS['RED']}FAIL: {fails}{COLORS['RESET']}")
    print("-" * 60)
    
    if return_results:
        # Return a list of tuples (benchmark_id, description, result)
        # Each result is a tuple (pass/fail, benchmark_id_description, status)
        # We need to extract the benchmark_id_description and status
        return [(result[1], result[2]) for result in results]
    
    return all(result[0] for result in results)


def run_all_remediations():
    """
    Run all filesystem kernel module remediations
    """
    print(f"{COLORS['BLUE']}Running Filesystem Kernel Module Remediations...{COLORS['RESET']}")
    
    remediation_functions = [
        ("cramfs", remediate_cramfs),
        ("freevxfs", remediate_freevxfs),
        ("jffs2", remediate_jffs2),
        ("hfs", remediate_hfs),
        ("hfsplus", remediate_hfsplus),
        ("squashfs", remediate_squashfs),
        ("udf", remediate_udf),
        ("FAT", remediate_fat)
    ]
    
    for module_name, remediate_func in remediation_functions:
        print(f"\n{COLORS['BLUE']}Remediating {module_name}...{COLORS['RESET']}")
        remediate_func()
    
    # Verify remediations by running audits again
    print("\n" + "=" * 60)
    print(f"{COLORS['BLUE']}Verifying remediations...{COLORS['RESET']}")
    all_pass = run_all_audits()
    
    if all_pass:
        print(f"\n{COLORS['GREEN']}✅ All filesystem kernel module remediations completed successfully!{COLORS['RESET']}")
    else:
        print(f"\n{COLORS['YELLOW']}⚠️ Some filesystem kernel module remediations failed. Manual intervention may be required.{COLORS['RESET']}")
    
    return all_pass


def main():
    """
    Main function to parse arguments and run appropriate functions
    """
    if len(sys.argv) < 2:
        print("Error: Missing required argument.")
        print("Usage: python3 fs_kernel_modules.py [audit|remediate]")
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
        print("Usage: python3 fs_kernel_modules.py [audit|remediate]")
        sys.exit(1)


if __name__ == "__main__":
    main()