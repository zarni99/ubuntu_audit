#!/usr/bin/env python3

"""
CIS Ubuntu 22.04 LTS Benchmark Audit and Remediation Controller

This script acts as the main controller for running all CIS Benchmark audit
and remediation modules for Ubuntu 22.04 LTS.

Usage:
    python3 cis_audit.py audit [module_name]     # Run audit checks for specific module or all
    python3 cis_audit.py remediate [module_name] # Run remediations for specific module or all
    python3 cis_audit.py --help-modules         # List all available modules and submodules
    
Optional flags:
    --technical  # Display results in technical format instead of user-friendly format
    --modules MODULE1 MODULE2 ...  # Specify multiple modules to audit/remediate

Examples:
    # Run all audit checks with user-friendly output
    python3 cis_audit.py audit

    # Run audit checks for a specific module with technical output
    python3 cis_audit.py audit package_management --technical

    # Run audit checks for multiple specific modules
    python3 cis_audit.py audit --modules package_management bootloader

    # Run all remediations with user-friendly output
    python3 cis_audit.py remediate

    # Run remediations for a specific module
    python3 cis_audit.py remediate bootloader
"""

# ANSI color codes
COLORS = {
    'GREEN': '\033[92m',  # Green for PASS/SECURE
    'RED': '\033[91m',    # Red for FAIL/VULNERABLE
    'YELLOW': '\033[93m', # Yellow for warnings
    'BLUE': '\033[94m',   # Blue for section headers
    'RESET': '\033[0m'    # Reset to default color
}

import sys
import importlib
import argparse
import io

# Import modules from the new structure
from modules.kernel import fs_modules
from modules.filesystem import partitions
from modules.package_management import repositories, updates
from modules.access_control import apparmor
from modules.bootloader import configuration
from modules.process_hardening import process_restrictions
from modules.command_line_warning import warning_banners

# Dictionary of user-friendly explanations for each benchmark
USER_FRIENDLY_EXPLANATIONS = {
    "1.1.1": {
        "title": "Filesystem Kernel Modules",
        "overview": "These checks ensure that unnecessary and potentially vulnerable filesystem modules are disabled.",
        "importance": "Disabling unnecessary kernel modules reduces the attack surface of the system and minimizes potential security vulnerabilities.",
        "pass_meaning": "The module is either not available or properly disabled, which is good for security.",
        "fail_meaning": "The module can be loaded, which poses a potential security risk.",
        "remediation_explanation": "The system will create configuration files that prevent these modules from being loaded.",
        "modules": {
            "cramfs": "An old, compressed read-only filesystem that is rarely needed in modern systems.",
            "freevxfs": "The Veritas filesystem driver, which is not commonly used and may contain vulnerabilities.",
            "jffs2": "A filesystem designed for flash devices, not typically needed on server systems.",
            "hfs": "Apple's legacy Hierarchical File System, rarely needed on Linux servers.",
            "hfsplus": "Apple's HFS+ filesystem, rarely needed on Linux servers.",
            "squashfs": "A compressed read-only filesystem, often used in live CDs but not typically needed on servers.",
            "udf": "Universal Disk Format, used for DVDs and optical media, rarely needed on servers.",
            "fat": "The FAT filesystem (including VFAT), primarily used for compatibility with Windows."
        }
    },
    "1.1.2": {
        "title": "Filesystem Partition Configuration",
        "overview": "These checks ensure that critical filesystem partitions are properly configured with appropriate mount options.",
        "importance": "Properly configured partitions with appropriate mount options help prevent privilege escalation and protect against various security threats.",
        "pass_meaning": "The partition is properly configured with the required mount options.",
        "fail_meaning": "The partition is either not properly configured or missing required security options.",
        "remediation_explanation": "Filesystem partition remediations require manual intervention. The system will provide instructions for manually configuring the partitions with appropriate mount options in /etc/fstab.",
        "modules": {
            "/tmp partition": "A separate partition for temporary files that prevents filling up the root filesystem and provides security controls.",
            "/tmp nodev": "Prevents device files from being created in /tmp, which could be used for privilege escalation.",
            "/tmp nosuid": "Prevents setuid programs in /tmp from changing the effective user ID, reducing privilege escalation risks.",
            "/tmp noexec": "Prevents execution of binaries in /tmp, which is a common location for malware to store executable files.",
            "/dev/shm partition": "A temporary filesystem in memory that needs proper security controls.",
            "/dev/shm nodev": "Prevents device files from being created in shared memory, which could be used for privilege escalation.",
            "/dev/shm nosuid": "Prevents setuid programs in shared memory from changing the effective user ID.",
            "/dev/shm noexec": "Prevents execution of binaries in shared memory, reducing the risk of memory-based attacks."
        }
    },
    "1.2.1": {
        "title": "Package Repositories",
        "overview": "These checks ensure that package repositories are properly configured and secured.",
        "importance": "Properly configured package repositories ensure that software is obtained from trusted sources and that package integrity is verified.",
        "pass_meaning": "The package repositories are properly configured and secured.",
        "fail_meaning": "The package repositories are not properly configured or secured, which could lead to compromised software.",
        "remediation_explanation": "The system will provide instructions for properly configuring package repositories and GPG keys.",
        "modules": {
            "GPG keys": "Cryptographic keys used to verify the authenticity of packages.",
            "package repositories": "Sources from which software packages are downloaded and installed."
        }
    },
    "1.2.2": {
        "title": "Package Updates",
        "overview": "These checks ensure that the system is configured to receive security updates.",
        "importance": "Regular security updates are critical for maintaining system security and addressing known vulnerabilities.",
        "pass_meaning": "The system is properly configured to receive security updates.",
        "fail_meaning": "The system is not properly configured to receive security updates, which could leave it vulnerable.",
        "remediation_explanation": "The system will provide instructions for configuring automatic security updates.",
        "modules": {
            "updates": "Configuration for receiving and applying security updates."
        }
    },
    "1.3.1": {
        "title": "AppArmor Configuration",
        "overview": "These checks ensure that AppArmor is properly installed, enabled, and configured.",
        "importance": "AppArmor provides Mandatory Access Control (MAC) which restricts programs to a limited set of resources, reducing the potential damage from compromised software.",
        "pass_meaning": "AppArmor is properly installed, enabled, and configured.",
        "fail_meaning": "AppArmor is not properly installed, enabled, or configured, which could leave the system vulnerable.",
        "remediation_explanation": "The system will provide instructions for installing, enabling, and configuring AppArmor.",
        "modules": {
            "AppArmor": "A Linux Security Module that provides Mandatory Access Control.",
            "AppArmor profiles": "Configuration files that define the resources a program can access."
        }
    },
    "1.4": {
        "title": "Bootloader Configuration",
        "overview": "These checks ensure that the bootloader is properly secured.",
        "importance": "A properly secured bootloader prevents unauthorized users from modifying boot parameters or booting into single user mode.",
        "pass_meaning": "The bootloader is properly secured.",
        "fail_meaning": "The bootloader is not properly secured, which could allow unauthorized access.",
        "remediation_explanation": "The system will provide instructions for securing the bootloader.",
        "modules": {
            "bootloader password": "A password that restricts access to the bootloader.",
            "bootloader permissions": "File permissions that prevent unauthorized modification of bootloader configuration."
        }
    },
    "1.5": {
        "title": "Process Hardening",
        "overview": "These checks ensure that additional process hardening measures are in place.",
        "importance": "Process hardening measures help prevent exploitation of vulnerabilities in running processes.",
        "pass_meaning": "The process hardening measure is properly configured.",
        "fail_meaning": "The process hardening measure is not properly configured, which could leave processes vulnerable.",
        "remediation_explanation": "The system will provide instructions for configuring process hardening measures.",
        "modules": {
            "address space layout randomization": "A security technique that randomizes memory addresses to make exploitation more difficult.",
            "ptrace scope": "Controls which processes can use ptrace to examine the memory and registers of other processes.",
            "core dumps": "Memory snapshots created when a program crashes, which could contain sensitive information.",
            "prelink": "A program that modifies ELF binaries to speed up loading, but can interfere with security measures.",
            "automatic error reporting": "A feature that sends crash reports, which could contain sensitive information."
        }
    },
    "1.6": {
        "title": "Command Line Warning Banners",
        "overview": "These checks ensure that appropriate warning banners are displayed to users.",
        "importance": "Warning banners inform users about authorized use of the system and may have legal implications.",
        "pass_meaning": "The warning banner is properly configured.",
        "fail_meaning": "The warning banner is not properly configured, which could have legal implications.",
        "remediation_explanation": "The system will provide instructions for configuring warning banners.",
        "modules": {
            "message of the day": "A message displayed to users when they log in.",
            "local login warning": "A warning displayed to users logging in locally.",
            "remote login warning": "A warning displayed to users logging in remotely.",
            "su command access": "Controls which users can use the su command to become root."
        }
    }
    # Add more sections as they are implemented
}

# List of all modules to run (will be expanded as more modules are added)
MODULES = [
    {
        "name": "kernel",
        "submodules": [
            {
                "name": "fs_modules",
                "module": fs_modules,
                "title": "1.1.1 Filesystem Kernel Modules",
                "description": "Ensure unnecessary filesystem modules are disabled"
            }
        ]
    },
    {
        "name": "filesystem",
        "submodules": [
            {
                "name": "partitions",
                "module": partitions,
                "title": "1.1.2 Filesystem Partition Configuration",
                "description": "Ensure proper filesystem partitioning and mounting"
            }
        ]
    },
    {
        "name": "package_management",
        "submodules": [
            {
                "name": "repositories",
                "module": repositories,
                "title": "1.2.1 Configure Package Repositories",
                "description": "Ensure package repositories are properly configured"
            },
            {
                "name": "updates",
                "module": updates,
                "title": "1.2.2 Configure Package Updates",
                "description": "Ensure package updates are properly configured"
            }
        ]
    },
    {
        "name": "access_control",
        "submodules": [
            {
                "name": "apparmor",
                "module": apparmor,
                "title": "1.3.1 Configure AppArmor",
                "description": "Ensure AppArmor is properly configured"
            }
        ]
    },
    {
        "name": "bootloader",
        "submodules": [
            {
                "name": "configuration",
                "module": configuration,
                "title": "1.4 Configure Bootloader",
                "description": "Ensure bootloader is properly configured"
            }
        ]
    },
    {
        "name": "process_hardening",
        "submodules": [
            {
                "name": "process_restrictions",
                "module": process_restrictions,
                "title": "1.5 Configure Additional Process Hardening",
                "description": "Ensure additional process hardening measures are in place"
            }
        ]
    },
    {
        "name": "command_line_warning",
        "submodules": [
            {
                "name": "warning_banners",
                "module": warning_banners,
                "title": "1.6 Configure Command Line Warning Banners",
                "description": "Ensure command line warning banners are properly configured"
            }
        ]
    },
    # {
    #     "name": "services",
    #     "submodules": [
    #         {
    #             "name": "service_clients",
    #             "module": None,  # Will be imported when implemented
    #             "title": "2.1-2.4 Services",
    #             "description": "Ensure unnecessary services are disabled"
    #         }
    #     ]
    # },
]


def print_section_header(title, description):
    """
    Print a formatted section header
    """
    print("\n" + "=" * 80)
    print(f"{COLORS['BLUE']}CIS Benchmark Section: {title}{COLORS['RESET']}")
    print(f"{COLORS['BLUE']}Description: {description}{COLORS['RESET']}")
    print("=" * 80)


def print_user_friendly_header(section_id, title):
    """
    Print a user-friendly section header with explanation
    """
    section_info = USER_FRIENDLY_EXPLANATIONS.get(section_id, {})
    
    print("\n" + "=" * 80)
    print(f"Security Check: {title}")
    print("=" * 80)
    
    if section_info:
        print(f"\nWhat this means: {section_info.get('overview', '')}")
        print(f"\nWhy it's important: {section_info.get('importance', '')}")
        print("\nWhat the results mean:")
        print(f"  {COLORS['GREEN']}✅ PASS:{COLORS['RESET']} {section_info.get('pass_meaning', '')}")
        print(f"  {COLORS['RED']}❌ FAIL:{COLORS['RESET']} {section_info.get('fail_meaning', '')}")
        print("\n" + "-" * 80)


def explain_module_result(module_name, result, section_id):
    """
    Provide a user-friendly explanation of a module check result
    """
    section_info = USER_FRIENDLY_EXPLANATIONS.get(section_id, {})
    module_info = section_info.get('modules', {}).get(module_name, "")
    
    if result:
        status = f"{COLORS['GREEN']}✅ SECURE{COLORS['RESET']}"
    else:
        status = f"{COLORS['RED']}❌ VULNERABLE{COLORS['RESET']}"
    
    print(f"\n{status}: {module_name} module")
    if module_info:
        print(f"What is it: {module_info}")
    
    if result:
        print(f"{COLORS['GREEN']}Status: This module is properly secured on your system.{COLORS['RESET']}")
    else:
        print(f"{COLORS['RED']}Status: This module is not properly secured and poses a potential risk.{COLORS['RESET']}")
        print(f"Recommendation: Run the remediation to secure this module.")


def filter_modules(target_module):
    """
    Filter modules based on the target module name
    """
    if target_module == "all":
        return MODULES
    
    filtered_modules = []
    
    for module_group in MODULES:
        if module_group["name"] == target_module:
            filtered_modules.append(module_group)
            continue
            
        filtered_submodules = []
        for submodule in module_group["submodules"]:
            if submodule["name"] == target_module:
                filtered_submodules.append(submodule)
                
        if filtered_submodules:
            filtered_module_group = module_group.copy()
            filtered_module_group["submodules"] = filtered_submodules
            filtered_modules.append(filtered_module_group)
    
    return filtered_modules


def run_audits(target_module="all", user_friendly=True):
    """
    Run audit functions from selected modules with user-friendly output by default
    """
    print(f"\n🔍 Starting CIS Ubuntu 22.04 LTS Benchmark Audit for {target_module}...\n")
    
    filtered_modules = filter_modules(target_module)
    
    if not filtered_modules:
        print(f"Error: Module '{target_module}' not found.")
        print("Available modules:")
        for module_group in MODULES:
            print(f"  - {module_group['name']} (group)")
            for submodule in module_group["submodules"]:
                print(f"    - {submodule['name']}")
        return False
    
    all_passed = True
    
    for module_group in filtered_modules:
        for submodule in module_group["submodules"]:
            if submodule["module"] is not None:
                if user_friendly:
                    # Handle user-friendly output based on module title
                    if submodule["title"].startswith("1.1.1"):
                        section_id = "1.1.1"
                    elif submodule["title"].startswith("1.1.2"):
                        section_id = "1.1.2"
                    elif submodule["title"].startswith("1.2.1"):
                        section_id = "1.2.1"
                    elif submodule["title"].startswith("1.2.2"):
                        section_id = "1.2.2"
                    elif submodule["title"].startswith("1.3.1"):
                        section_id = "1.3.1"
                    elif submodule["title"].startswith("1.4"):
                        section_id = "1.4"
                    elif submodule["title"].startswith("1.5"):
                        section_id = "1.5"
                    elif submodule["title"].startswith("1.6"):
                        section_id = "1.6"
                    else:
                        # Default to standard output if no user-friendly explanation exists
                        print_section_header(submodule["title"], submodule["description"])
                        result = submodule["module"].run_all_audits()
                        if not result:
                            all_passed = False
                        continue
                    
                    print_user_friendly_header(section_id, submodule["title"])
                    
                    # Capture the technical output
                    original_stdout = sys.stdout
                    sys.stdout = io.StringIO()
                    
                    # Run the actual checks
                    results = submodule["module"].run_all_audits(return_results=True)
                    
                    # Restore stdout
                    technical_output = sys.stdout.getvalue()
                    sys.stdout = original_stdout
                    
                    # Process and display user-friendly results based on section_id
                    if section_id == "1.1.1":
                        # Filesystem kernel modules
                        module_results = {
                            "cramfs": next((r[1] for r in results if "1.1.1.1" in r[0]), False),
                            "freevxfs": next((r[1] for r in results if "1.1.1.2" in r[0]), False),
                            "jffs2": next((r[1] for r in results if "1.1.1.3" in r[0]), False),
                            "hfs": next((r[1] for r in results if "1.1.1.4" in r[0]), False),
                            "hfsplus": next((r[1] for r in results if "1.1.1.5" in r[0]), False),
                            "squashfs": next((r[1] for r in results if "1.1.1.6" in r[0]), False),
                            "udf": next((r[1] for r in results if "1.1.1.7" in r[0]), False),
                            "fat": next((r[1] for r in results if "1.1.1.8" in r[0]), False)
                        }
                    elif section_id == "1.1.2":
                        # Filesystem partitions
                        module_results = {
                            "/tmp partition": next((r[1] for r in results if "1.1.2.1" in r[0]), False),
                            "/tmp nodev": next((r[1] for r in results if "1.1.2.2" in r[0]), False),
                            "/tmp nosuid": next((r[1] for r in results if "1.1.2.3" in r[0]), False),
                            "/tmp noexec": next((r[1] for r in results if "1.1.2.4" in r[0]), False),
                            "/dev/shm partition": next((r[1] for r in results if "1.1.2.5" in r[0]), False),
                            "/dev/shm nodev": next((r[1] for r in results if "1.1.2.6" in r[0]), False),
                            "/dev/shm nosuid": next((r[1] for r in results if "1.1.2.7" in r[0]), False),
                            "/dev/shm noexec": next((r[1] for r in results if "1.1.2.8" in r[0]), False)
                        }
                    
                    for module_name, result in module_results.items():
                        explain_module_result(module_name, result, section_id)
                    
                    # Summary
                    passed = all(module_results.values())
                    if not passed:
                        all_passed = False
                        
                    print("\n" + "-" * 80)
                    if passed:
                        print(f"\n{COLORS['GREEN']}✅ Overall Result: SECURE{COLORS['RESET']}")
                        print(f"{COLORS['GREEN']}All checks passed. Your system is properly configured.{COLORS['RESET']}")
                    else:
                        print(f"\n{COLORS['YELLOW']}⚠️ Overall Result: VULNERABLE{COLORS['RESET']}")
                        print(f"{COLORS['RED']}Some checks failed. Your system may be at risk.{COLORS['RESET']}")
                        print("Recommendation: Run the remediation to address these issues.")
                        print(f"Command: python3 cis_audit.py remediate {target_module}")
                else:
                    # Standard technical output
                    print_section_header(submodule["title"], submodule["description"])
                    # Call the module's run_all_audits function
                    result = submodule["module"].run_all_audits()
                    if not result:
                        all_passed = False
    
    print("\n" + "=" * 80)
    if all_passed:
        print(f"\n{COLORS['GREEN']}✅ All audits completed successfully. System is compliant with benchmarks.{COLORS['RESET']}")
    else:
        print(f"\n{COLORS['YELLOW']}⚠️  All audits completed. Some checks failed. Run with 'remediate' to fix issues.{COLORS['RESET']}")
    
    return all_passed


def run_remediations(target_module="all", user_friendly=True):
    """
    Run remediation functions from selected modules with user-friendly output by default
    """
    print(f"\n🔧 Starting CIS Ubuntu 22.04 LTS Benchmark Remediation for {target_module}...\n")
    
    filtered_modules = filter_modules(target_module)
    
    if not filtered_modules:
        print(f"Error: Module '{target_module}' not found.")
        print("Available modules:")
        for module_group in MODULES:
            print(f"  - {module_group['name']} (group)")
            for submodule in module_group["submodules"]:
                print(f"    - {submodule['name']}")
        return False
    
    for module_group in filtered_modules:
        for submodule in module_group["submodules"]:
            if submodule["module"] is not None:
                if user_friendly:
                    # Handle user-friendly output based on module title
                    if submodule["title"].startswith("1.1.1"):
                        section_id = "1.1.1"
                    elif submodule["title"].startswith("1.1.2"):
                        section_id = "1.1.2"
                    elif submodule["title"].startswith("1.2.1"):
                        section_id = "1.2.1"
                    elif submodule["title"].startswith("1.2.2"):
                        section_id = "1.2.2"
                    elif submodule["title"].startswith("1.3.1"):
                        section_id = "1.3.1"
                    elif submodule["title"].startswith("1.4"):
                        section_id = "1.4"
                    elif submodule["title"].startswith("1.5"):
                        section_id = "1.5"
                    elif submodule["title"].startswith("1.6"):
                        section_id = "1.6"
                    else:
                        # Default to standard output if no user-friendly explanation exists
                        print_section_header(submodule["title"], submodule["description"])
                        submodule["module"].run_all_remediations()
                        continue
                    
                    section_info = USER_FRIENDLY_EXPLANATIONS.get(section_id, {})
                    print_user_friendly_header(section_id, submodule["title"])
                    
                    print("\nApplying security fixes...")
                    if section_info:
                        print(f"What this will do: {section_info.get('remediation_explanation', '')}")
                    
                    # Run the actual remediation
                    submodule["module"].run_all_remediations()
                    
                    print(f"\n{COLORS['GREEN']}✅ Remediation completed!{COLORS['RESET']}")
                    
                    if section_id == "1.1.1":
                        print(f"{COLORS['GREEN']}The system has been secured against the identified vulnerabilities.{COLORS['RESET']}")
                    elif section_id == "1.1.2":
                        print(f"{COLORS['YELLOW']}Note: Filesystem partition remediations require manual intervention.{COLORS['RESET']}")
                        print(f"{COLORS['YELLOW']}Please review the recommendations and apply them manually.{COLORS['RESET']}")
                        print(f"{COLORS['YELLOW']}No automatic remediation is performed for these checks.{COLORS['RESET']}")
                        
                    print("\nTo verify that all issues have been fixed, run:")
                    print(f"python3 cis_audit.py audit {target_module}")
                else:
                    # Standard technical output
                    print_section_header(submodule["title"], submodule["description"])
                    # Call the module's run_all_remediations function
                    submodule["module"].run_all_remediations()
    
    print("\n" + "=" * 80)
    print(f"\n{COLORS['GREEN']}✅ Remediation completed. Run audit again to verify compliance.{COLORS['RESET']}")
    return True


def list_available_modules():
    """
    Print a formatted list of all available modules and submodules
    """
    print("\nAvailable Modules:\n")
    print("Module Groups:")
    for module_group in MODULES:
        print(f"  - {module_group['name']}")
        print(f"    Description: Group of modules for {module_group['name']} security checks")
        print("    Submodules:")
        for submodule in module_group["submodules"]:
            print(f"      - {submodule['name']}")
            print(f"        Title: {submodule['title']}")
            print(f"        Description: {submodule['description']}")
        print()

def main():
    """
    Main function to parse arguments and run appropriate functions
    """
    parser = argparse.ArgumentParser(
        description="CIS Ubuntu 22.04 LTS Benchmark Audit and Remediation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Run all audit checks with user-friendly output
  python3 cis_audit.py audit

  # Run audit checks for a specific module with technical output
  python3 cis_audit.py audit package_management --technical

  # Run audit checks for a specific submodule
  python3 cis_audit.py audit repositories

  # Run all remediations with user-friendly output
  python3 cis_audit.py remediate

  # Run remediations for a specific module
  python3 cis_audit.py remediate bootloader

  # List all available modules and submodules
  python3 cis_audit.py --help-modules
'''
    )
    
    # Add a mutually exclusive group for the main action vs. help-modules
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("action", choices=["audit", "remediate"], help="Action to perform", nargs="?", default=None)
    action_group.add_argument("--help-modules", action="store_true", help="List all available modules and submodules")
    
    parser.add_argument("module", nargs="?", default="all", help="Module to audit/remediate (default: all)")
    parser.add_argument("--technical", action="store_true", help="Display results in technical format instead of user-friendly format")
    parser.add_argument("--modules", nargs="+", help="Specify multiple modules to audit/remediate")
    
    args = parser.parse_args()
    
    # Handle the --help-modules flag
    if args.help_modules:
        list_available_modules()
        return
    
    # Default to user-friendly output unless --technical flag is specified
    user_friendly = not args.technical
    
    # Handle multiple modules if specified with --modules
    if args.modules:
        all_passed = True
        for module in args.modules:
            if args.action == "audit":
                result = run_audits(module, user_friendly)
                if not result:
                    all_passed = False
            elif args.action == "remediate":
                run_remediations(module, user_friendly)
        return all_passed
    else:
        # Handle single module specified as positional argument
        if args.action == "audit":
            return run_audits(args.module, user_friendly)
        elif args.action == "remediate":
            return run_remediations(args.module, user_friendly)


if __name__ == "__main__":
    main()