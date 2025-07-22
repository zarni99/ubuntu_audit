#!/usr/bin/env python3

"""
CIS Ubuntu 22.04 LTS Benchmark Audit and Remediation Controller

This script acts as the main controller for running all CIS Benchmark audit
and remediation modules for Ubuntu 22.04 LTS.

Usage:
    python3 cis_audit.py audit     # Run all audit checks
    python3 cis_audit.py remediate # Run all remediations
"""

import sys
import importlib

# Import existing modules
import fs_kernel_modules

# List of all modules to run (will be expanded as more modules are added)
MODULES = [
    {
        "name": "fs_kernel_modules",
        "module": fs_kernel_modules,
        "title": "1.1.1 Filesystem Kernel Modules",
        "description": "Ensure unnecessary filesystem modules are disabled"
    },
    # Future modules will be added here, for example:
    # {
    #     "name": "fs_partition_config",
    #     "module": None,  # Will be imported when implemented
    #     "title": "1.1.2-1.1.23 Filesystem Configuration",
    #     "description": "Ensure proper filesystem partitioning and mounting"
    # },
    # {
    #     "name": "services",
    #     "module": None,  # Will be imported when implemented
    #     "title": "2.1-2.4 Services",
    #     "description": "Ensure unnecessary services are disabled"
    # },
    # {
    #     "name": "ssh_hardening",
    #     "module": None,  # Will be imported when implemented
    #     "title": "5.2 SSH Server Configuration",
    #     "description": "Ensure SSH server is securely configured"
    # },
]


def print_section_header(title, description):
    """
    Print a formatted section header
    """
    print("\n" + "=" * 80)
    print(f"CIS Benchmark Section: {title}")
    print(f"Description: {description}")
    print("=" * 80)


def run_all_audits():
    """
    Run audit functions from all modules
    """
    print("\n🔍 Starting CIS Ubuntu 22.04 LTS Benchmark Audit...\n")
    
    all_passed = True
    for module_info in MODULES:
        if module_info["module"] is not None:
            print_section_header(module_info["title"], module_info["description"])
            # Call the module's run_all_audits function
            result = module_info["module"].run_all_audits()
            if not result:
                all_passed = False
    
    print("\n" + "=" * 80)
    if all_passed:
        print("\n✅ All audits completed successfully. System is compliant with benchmarks.")
    else:
        print("\n⚠️  All audits completed. Some checks failed. Run with 'remediate' to fix issues.")
    
    return all_passed


def run_all_remediations():
    """
    Run remediation functions from all modules
    """
    print("\n🔧 Starting CIS Ubuntu 22.04 LTS Benchmark Remediation...\n")
    
    for module_info in MODULES:
        if module_info["module"] is not None:
            print_section_header(module_info["title"], module_info["description"])
            # Call the module's run_all_remediations function
            module_info["module"].run_all_remediations()
    
    print("\n" + "=" * 80)
    print("\n✅ Remediation completed. Run audit again to verify compliance.")


def main():
    """
    Main function to parse arguments and run appropriate functions
    """
    if len(sys.argv) < 2:
        print("Error: Missing required argument.")
        print("Usage: python3 cis_audit.py [audit|remediate]")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    
    if mode == "audit":
        run_all_audits()
    elif mode == "remediate":
        run_all_remediations()
    else:
        print(f"Error: Invalid mode '{mode}'.")
        print("Usage: python3 cis_audit.py [audit|remediate]")
        sys.exit(1)


if __name__ == "__main__":
    main()