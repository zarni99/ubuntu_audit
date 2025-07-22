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
    stdout, stderr, rc = _run_command(f"lsmod | grep {module_name}")
    return len(stdout) > 0


def _is_module_available(module_name):
    """
    Check if a kernel module is available to be loaded
    """
    stdout, stderr, rc = _run_command(f"modprobe -n -v {module_name}")
    return not ("not found" in stdout or "not found" in stderr)


def _is_module_disabled(module_name):
    """
    Check if a kernel module is disabled
    """
    stdout, stderr, rc = _run_command(f"modprobe -n -v {module_name}")
    return "install /bin/true" in stdout or "install /bin/false" in stdout


def _create_remediation_file(module_name):
    """
    Create a remediation file content for disabling a module
    """
    return f"# Disable {module_name} module\ninstall {module_name} /bin/true"


def check_cramfs():
    """
    Audit for CIS 1.1.1.1 Ensure cramfs kernel module is not available
    """
    module_name = "cramfs"
    print(f"\n[*] Checking if {module_name} kernel module is disabled...")
    
    # Check if module is loaded
    if _is_module_loaded(module_name):
        print(f"[-] FAIL: {module_name} module is currently loaded")
        remediation = f"rmmod {module_name}"
        print(f"    Remediation: {remediation}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is not loaded")
    
    # Check if module is disabled
    if not _is_module_disabled(module_name) and _is_module_available(module_name):
        print(f"[-] FAIL: {module_name} module can be loaded")
        remediation_file = f"/etc/modprobe.d/{module_name}.conf"
        remediation_content = _create_remediation_file(module_name)
        remediation = f"echo '{remediation_content}' > {remediation_file}"
        print(f"    Remediation: Create {remediation_file} with:")
        print(f"    {remediation_content}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is disabled or not available")
    
    return True, ""


def remediate_cramfs():
    """
    Remediate CIS 1.1.1.1 Ensure cramfs kernel module is not available
    """
    module_name = "cramfs"
    print(f"\n[*] Remediating {module_name} kernel module...")
    
    # Unload the module if it's loaded
    if _is_module_loaded(module_name):
        stdout, stderr, rc = _run_command(f"rmmod {module_name}")
        if rc == 0:
            print(f"[+] Successfully unloaded {module_name} module")
        else:
            print(f"[-] Failed to unload {module_name} module: {stderr}")
            return False
    
    # Create or update the configuration file to disable the module
    remediation_file = f"/etc/modprobe.d/{module_name}.conf"
    remediation_content = _create_remediation_file(module_name)
    
    try:
        with open(remediation_file, 'w') as f:
            f.write(remediation_content)
        print(f"[+] Successfully created {remediation_file} to disable {module_name}")
        return True
    except Exception as e:
        print(f"[-] Failed to create {remediation_file}: {str(e)}")
        return False


def check_freevxfs():
    """
    Audit for CIS 1.1.1.2 Ensure freevxfs kernel module is not available
    """
    module_name = "freevxfs"
    print(f"\n[*] Checking if {module_name} kernel module is disabled...")
    
    # Check if module is loaded
    if _is_module_loaded(module_name):
        print(f"[-] FAIL: {module_name} module is currently loaded")
        remediation = f"rmmod {module_name}"
        print(f"    Remediation: {remediation}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is not loaded")
    
    # Check if module is disabled
    if not _is_module_disabled(module_name) and _is_module_available(module_name):
        print(f"[-] FAIL: {module_name} module can be loaded")
        remediation_file = f"/etc/modprobe.d/{module_name}.conf"
        remediation_content = _create_remediation_file(module_name)
        remediation = f"echo '{remediation_content}' > {remediation_file}"
        print(f"    Remediation: Create {remediation_file} with:")
        print(f"    {remediation_content}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is disabled or not available")
    
    return True, ""


def remediate_freevxfs():
    """
    Remediate CIS 1.1.1.2 Ensure freevxfs kernel module is not available
    """
    module_name = "freevxfs"
    print(f"\n[*] Remediating {module_name} kernel module...")
    
    # Unload the module if it's loaded
    if _is_module_loaded(module_name):
        stdout, stderr, rc = _run_command(f"rmmod {module_name}")
        if rc == 0:
            print(f"[+] Successfully unloaded {module_name} module")
        else:
            print(f"[-] Failed to unload {module_name} module: {stderr}")
            return False
    
    # Create or update the configuration file to disable the module
    remediation_file = f"/etc/modprobe.d/{module_name}.conf"
    remediation_content = _create_remediation_file(module_name)
    
    try:
        with open(remediation_file, 'w') as f:
            f.write(remediation_content)
        print(f"[+] Successfully created {remediation_file} to disable {module_name}")
        return True
    except Exception as e:
        print(f"[-] Failed to create {remediation_file}: {str(e)}")
        return False


def check_jffs2():
    """
    Audit for CIS 1.1.1.3 Ensure jffs2 kernel module is not available
    """
    module_name = "jffs2"
    print(f"\n[*] Checking if {module_name} kernel module is disabled...")
    
    # Check if module is loaded
    if _is_module_loaded(module_name):
        print(f"[-] FAIL: {module_name} module is currently loaded")
        remediation = f"rmmod {module_name}"
        print(f"    Remediation: {remediation}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is not loaded")
    
    # Check if module is disabled
    if not _is_module_disabled(module_name) and _is_module_available(module_name):
        print(f"[-] FAIL: {module_name} module can be loaded")
        remediation_file = f"/etc/modprobe.d/{module_name}.conf"
        remediation_content = _create_remediation_file(module_name)
        remediation = f"echo '{remediation_content}' > {remediation_file}"
        print(f"    Remediation: Create {remediation_file} with:")
        print(f"    {remediation_content}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is disabled or not available")
    
    return True, ""


def remediate_jffs2():
    """
    Remediate CIS 1.1.1.3 Ensure jffs2 kernel module is not available
    """
    module_name = "jffs2"
    print(f"\n[*] Remediating {module_name} kernel module...")
    
    # Unload the module if it's loaded
    if _is_module_loaded(module_name):
        stdout, stderr, rc = _run_command(f"rmmod {module_name}")
        if rc == 0:
            print(f"[+] Successfully unloaded {module_name} module")
        else:
            print(f"[-] Failed to unload {module_name} module: {stderr}")
            return False
    
    # Create or update the configuration file to disable the module
    remediation_file = f"/etc/modprobe.d/{module_name}.conf"
    remediation_content = _create_remediation_file(module_name)
    
    try:
        with open(remediation_file, 'w') as f:
            f.write(remediation_content)
        print(f"[+] Successfully created {remediation_file} to disable {module_name}")
        return True
    except Exception as e:
        print(f"[-] Failed to create {remediation_file}: {str(e)}")
        return False


def check_hfs():
    """
    Audit for CIS 1.1.1.4 Ensure hfs kernel module is not available
    """
    module_name = "hfs"
    print(f"\n[*] Checking if {module_name} kernel module is disabled...")
    
    # Check if module is loaded
    if _is_module_loaded(module_name):
        print(f"[-] FAIL: {module_name} module is currently loaded")
        remediation = f"rmmod {module_name}"
        print(f"    Remediation: {remediation}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is not loaded")
    
    # Check if module is disabled
    if not _is_module_disabled(module_name) and _is_module_available(module_name):
        print(f"[-] FAIL: {module_name} module can be loaded")
        remediation_file = f"/etc/modprobe.d/{module_name}.conf"
        remediation_content = _create_remediation_file(module_name)
        remediation = f"echo '{remediation_content}' > {remediation_file}"
        print(f"    Remediation: Create {remediation_file} with:")
        print(f"    {remediation_content}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is disabled or not available")
    
    return True, ""


def remediate_hfs():
    """
    Remediate CIS 1.1.1.4 Ensure hfs kernel module is not available
    """
    module_name = "hfs"
    print(f"\n[*] Remediating {module_name} kernel module...")
    
    # Unload the module if it's loaded
    if _is_module_loaded(module_name):
        stdout, stderr, rc = _run_command(f"rmmod {module_name}")
        if rc == 0:
            print(f"[+] Successfully unloaded {module_name} module")
        else:
            print(f"[-] Failed to unload {module_name} module: {stderr}")
            return False
    
    # Create or update the configuration file to disable the module
    remediation_file = f"/etc/modprobe.d/{module_name}.conf"
    remediation_content = _create_remediation_file(module_name)
    
    try:
        with open(remediation_file, 'w') as f:
            f.write(remediation_content)
        print(f"[+] Successfully created {remediation_file} to disable {module_name}")
        return True
    except Exception as e:
        print(f"[-] Failed to create {remediation_file}: {str(e)}")
        return False


def check_hfsplus():
    """
    Audit for CIS 1.1.1.5 Ensure hfsplus kernel module is not available
    """
    module_name = "hfsplus"
    print(f"\n[*] Checking if {module_name} kernel module is disabled...")
    
    # Check if module is loaded
    if _is_module_loaded(module_name):
        print(f"[-] FAIL: {module_name} module is currently loaded")
        remediation = f"rmmod {module_name}"
        print(f"    Remediation: {remediation}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is not loaded")
    
    # Check if module is disabled
    if not _is_module_disabled(module_name) and _is_module_available(module_name):
        print(f"[-] FAIL: {module_name} module can be loaded")
        remediation_file = f"/etc/modprobe.d/{module_name}.conf"
        remediation_content = _create_remediation_file(module_name)
        remediation = f"echo '{remediation_content}' > {remediation_file}"
        print(f"    Remediation: Create {remediation_file} with:")
        print(f"    {remediation_content}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is disabled or not available")
    
    return True, ""


def remediate_hfsplus():
    """
    Remediate CIS 1.1.1.5 Ensure hfsplus kernel module is not available
    """
    module_name = "hfsplus"
    print(f"\n[*] Remediating {module_name} kernel module...")
    
    # Unload the module if it's loaded
    if _is_module_loaded(module_name):
        stdout, stderr, rc = _run_command(f"rmmod {module_name}")
        if rc == 0:
            print(f"[+] Successfully unloaded {module_name} module")
        else:
            print(f"[-] Failed to unload {module_name} module: {stderr}")
            return False
    
    # Create or update the configuration file to disable the module
    remediation_file = f"/etc/modprobe.d/{module_name}.conf"
    remediation_content = _create_remediation_file(module_name)
    
    try:
        with open(remediation_file, 'w') as f:
            f.write(remediation_content)
        print(f"[+] Successfully created {remediation_file} to disable {module_name}")
        return True
    except Exception as e:
        print(f"[-] Failed to create {remediation_file}: {str(e)}")
        return False


def check_squashfs():
    """
    Audit for CIS 1.1.1.6 Ensure squashfs kernel module is not available
    """
    module_name = "squashfs"
    print(f"\n[*] Checking if {module_name} kernel module is disabled...")
    
    # Check if module is loaded
    if _is_module_loaded(module_name):
        print(f"[-] FAIL: {module_name} module is currently loaded")
        remediation = f"rmmod {module_name}"
        print(f"    Remediation: {remediation}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is not loaded")
    
    # Check if module is disabled
    if not _is_module_disabled(module_name) and _is_module_available(module_name):
        print(f"[-] FAIL: {module_name} module can be loaded")
        remediation_file = f"/etc/modprobe.d/{module_name}.conf"
        remediation_content = _create_remediation_file(module_name)
        remediation = f"echo '{remediation_content}' > {remediation_file}"
        print(f"    Remediation: Create {remediation_file} with:")
        print(f"    {remediation_content}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is disabled or not available")
    
    return True, ""


def remediate_squashfs():
    """
    Remediate CIS 1.1.1.6 Ensure squashfs kernel module is not available
    """
    module_name = "squashfs"
    print(f"\n[*] Remediating {module_name} kernel module...")
    
    # Unload the module if it's loaded
    if _is_module_loaded(module_name):
        stdout, stderr, rc = _run_command(f"rmmod {module_name}")
        if rc == 0:
            print(f"[+] Successfully unloaded {module_name} module")
        else:
            print(f"[-] Failed to unload {module_name} module: {stderr}")
            return False
    
    # Create or update the configuration file to disable the module
    remediation_file = f"/etc/modprobe.d/{module_name}.conf"
    remediation_content = _create_remediation_file(module_name)
    
    try:
        with open(remediation_file, 'w') as f:
            f.write(remediation_content)
        print(f"[+] Successfully created {remediation_file} to disable {module_name}")
        return True
    except Exception as e:
        print(f"[-] Failed to create {remediation_file}: {str(e)}")
        return False


def check_udf():
    """
    Audit for CIS 1.1.1.7 Ensure udf kernel module is not available
    """
    module_name = "udf"
    print(f"\n[*] Checking if {module_name} kernel module is disabled...")
    
    # Check if module is loaded
    if _is_module_loaded(module_name):
        print(f"[-] FAIL: {module_name} module is currently loaded")
        remediation = f"rmmod {module_name}"
        print(f"    Remediation: {remediation}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is not loaded")
    
    # Check if module is disabled
    if not _is_module_disabled(module_name) and _is_module_available(module_name):
        print(f"[-] FAIL: {module_name} module can be loaded")
        remediation_file = f"/etc/modprobe.d/{module_name}.conf"
        remediation_content = _create_remediation_file(module_name)
        remediation = f"echo '{remediation_content}' > {remediation_file}"
        print(f"    Remediation: Create {remediation_file} with:")
        print(f"    {remediation_content}")
        return False, remediation
    else:
        print(f"[+] PASS: {module_name} module is disabled or not available")
    
    return True, ""


def remediate_udf():
    """
    Remediate CIS 1.1.1.7 Ensure udf kernel module is not available
    """
    module_name = "udf"
    print(f"\n[*] Remediating {module_name} kernel module...")
    
    # Unload the module if it's loaded
    if _is_module_loaded(module_name):
        stdout, stderr, rc = _run_command(f"rmmod {module_name}")
        if rc == 0:
            print(f"[+] Successfully unloaded {module_name} module")
        else:
            print(f"[-] Failed to unload {module_name} module: {stderr}")
            return False
    
    # Create or update the configuration file to disable the module
    remediation_file = f"/etc/modprobe.d/{module_name}.conf"
    remediation_content = _create_remediation_file(module_name)
    
    try:
        with open(remediation_file, 'w') as f:
            f.write(remediation_content)
        print(f"[+] Successfully created {remediation_file} to disable {module_name}")
        return True
    except Exception as e:
        print(f"[-] Failed to create {remediation_file}: {str(e)}")
        return False


def check_fat():
    """
    Audit for CIS 1.1.1.8 Ensure FAT kernel module is not available
    """
    # FAT consists of multiple modules: fat, vfat, msdos
    modules = ["fat", "vfat", "msdos"]
    all_pass = True
    remediation_commands = []
    
    for module_name in modules:
        print(f"\n[*] Checking if {module_name} kernel module is disabled...")
        
        # Check if module is loaded
        if _is_module_loaded(module_name):
            print(f"[-] FAIL: {module_name} module is currently loaded")
            remediation = f"rmmod {module_name}"
            print(f"    Remediation: {remediation}")
            remediation_commands.append(remediation)
            all_pass = False
        else:
            print(f"[+] PASS: {module_name} module is not loaded")
        
        # Check if module is disabled
        if not _is_module_disabled(module_name) and _is_module_available(module_name):
            print(f"[-] FAIL: {module_name} module can be loaded")
            remediation_file = f"/etc/modprobe.d/{module_name}.conf"
            remediation_content = _create_remediation_file(module_name)
            remediation = f"echo '{remediation_content}' > {remediation_file}"
            print(f"    Remediation: Create {remediation_file} with:")
            print(f"    {remediation_content}")
            remediation_commands.append(remediation)
            all_pass = False
        else:
            print(f"[+] PASS: {module_name} module is disabled or not available")
    
    return all_pass, "\n".join(remediation_commands)


def remediate_fat():
    """
    Remediate CIS 1.1.1.8 Ensure FAT kernel module is not available
    """
    # FAT consists of multiple modules: fat, vfat, msdos
    modules = ["fat", "vfat", "msdos"]
    all_pass = True
    
    for module_name in modules:
        print(f"\n[*] Remediating {module_name} kernel module...")
        
        # Unload the module if it's loaded
        if _is_module_loaded(module_name):
            stdout, stderr, rc = _run_command(f"rmmod {module_name}")
            if rc == 0:
                print(f"[+] Successfully unloaded {module_name} module")
            else:
                print(f"[-] Failed to unload {module_name} module: {stderr}")
                all_pass = False
        
        # Create or update the configuration file to disable the module
        remediation_file = f"/etc/modprobe.d/{module_name}.conf"
        remediation_content = _create_remediation_file(module_name)
        
        try:
            with open(remediation_file, 'w') as f:
                f.write(remediation_content)
            print(f"[+] Successfully created {remediation_file} to disable {module_name}")
        except Exception as e:
            print(f"[-] Failed to create {remediation_file}: {str(e)}")
            all_pass = False
    
    return all_pass


def run_all_audits():
    """
    Run all filesystem kernel module audits
    """
    print("\n===== CIS Ubuntu 22.04 LTS Benchmark - Section 1.1.1 Filesystem Kernel Modules Audit =====")
    
    audit_functions = [
        ("1.1.1.1", "Ensure cramfs kernel module is not available", check_cramfs),
        ("1.1.1.2", "Ensure freevxfs kernel module is not available", check_freevxfs),
        ("1.1.1.3", "Ensure jffs2 kernel module is not available", check_jffs2),
        ("1.1.1.4", "Ensure hfs kernel module is not available", check_hfs),
        ("1.1.1.5", "Ensure hfsplus kernel module is not available", check_hfsplus),
        ("1.1.1.6", "Ensure squashfs kernel module is not available", check_squashfs),
        ("1.1.1.7", "Ensure udf kernel module is not available", check_udf),
        ("1.1.1.8", "Ensure FAT kernel module is not available", check_fat)
    ]
    
    results = []
    for section, description, check_func in audit_functions:
        print(f"\n==== {section} {description} ====")
        passed, remediation = check_func()
        results.append((section, description, passed))
    
    # Print summary
    print("\n\n===== SUMMARY =====")
    passed_count = sum(1 for _, _, passed in results if passed)
    total_count = len(results)
    
    print(f"\nPassed: {passed_count}/{total_count} checks")
    
    if passed_count == total_count:
        print("\n[+] All checks passed!")
    else:
        print("\n[-] Failed checks:")
        for section, description, passed in results:
            if not passed:
                print(f"    - {section} {description}")
        print("\nRun with remediation functions to fix the issues.")
    
    return passed_count == total_count


def run_all_remediations():
    """
    Run all filesystem kernel module remediations
    """
    print("\n===== CIS Ubuntu 22.04 LTS Benchmark - Section 1.1.1 Filesystem Kernel Modules Remediation =====")
    remediation_functions = [
        ("1.1.1.1", "Ensure cramfs kernel module is not available", remediate_cramfs),
        ("1.1.1.2", "Ensure freevxfs kernel module is not available", remediate_freevxfs),
        ("1.1.1.3", "Ensure jffs2 kernel module is not available", remediate_jffs2),
        ("1.1.1.4", "Ensure hfs kernel module is not available", remediate_hfs),
        ("1.1.1.5", "Ensure hfsplus kernel module is not available", remediate_hfsplus),
        ("1.1.1.6", "Ensure squashfs kernel module is not available", remediate_squashfs),
        ("1.1.1.7", "Ensure udf kernel module is not available", remediate_udf),
        ("1.1.1.8", "Ensure FAT kernel module is not available", remediate_fat)
    ]
    
    for section, description, remediate_func in remediation_functions:
        print(f"\n==== {section} {description} ====")
        remediate_func()
    
    # Run audit again to verify remediation
    print("\n\n===== Verifying Remediation =====")
    return run_all_audits()


def main():
    """
    Main function to run the script
    """
    if len(sys.argv) < 2:
        print("Usage: python fs_kernel_modules.py [audit|remediate]")
        sys.exit(1)
    
    action = sys.argv[1].lower()
    
    if action == "audit":
        run_all_audits()
    elif action == "remediate":
        run_all_remediations()
    else:
        print("Invalid action. Use 'audit' or 'remediate'.")
        sys.exit(1)


if __name__ == "__main__":
    main()