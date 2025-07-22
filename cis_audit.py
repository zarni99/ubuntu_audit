#!/usr/bin/env python3

"""
CIS Ubuntu 22.04 LTS Benchmark Audit and Remediation Controller

This script acts as the main controller for running all CIS Benchmark audit
and remediation modules for Ubuntu 22.04 LTS.

Usage:
    python3 cis_audit.py audit [module_name]     # Run audit checks for specific module or all
    python3 cis_audit.py remediate [module_name] # Run remediations for specific module or all
    
    Optional flags:
    --technical  # Display results in technical format instead of user-friendly format (which is now the default)
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


def main():
    """
    Main function to parse arguments and run appropriate functions
    """
    parser = argparse.ArgumentParser(description="CIS Ubuntu 22.04 LTS Benchmark Audit and Remediation Tool")
    parser.add_argument("action", choices=["audit", "remediate"], help="Action to perform")
    parser.add_argument("module", nargs="?", default="all", help="Module to audit/remediate (default: all)")
    parser.add_argument("--technical", action="store_true", help="Display results in technical format instead of user-friendly format")
    
    args = parser.parse_args()
    
    # Default to user-friendly output unless --technical flag is specified
    user_friendly = not args.technical
    
    if args.action == "audit":
        run_audits(args.module, user_friendly)
    elif args.action == "remediate":
        run_remediations(args.module, user_friendly)


if __name__ == "__main__":
    main()