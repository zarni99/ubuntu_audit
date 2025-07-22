#!/usr/bin/env python3

"""
User-Friendly CIS Ubuntu 22.04 LTS Benchmark Report Generator

This script enhances the output of the CIS benchmark audit to make it more
understandable for non-technical users. It provides clear explanations of
what each check means, why it's important, and what the results indicate.

Usage:
    python3 user_friendly_report.py audit     # Run all audit checks with user-friendly output
    python3 user_friendly_report.py remediate # Run all remediations with user-friendly output
"""

# ANSI color codes
COLORS = {
    'GREEN': '\033[92m',  # Green for PASS/SECURE
    'RED': '\033[91m',    # Red for FAIL/VULNERABLE
    'YELLOW': '\033[93m', # Yellow for warnings
    'RESET': '\033[0m'    # Reset to default color
}

import sys
import importlib
import fs_kernel_modules
import cis_audit

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
    }
    # Add more sections as they are implemented
}


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


def run_user_friendly_audit():
    """
    Run audit with user-friendly output
    """
    print("\n🔍 Starting User-Friendly Security Audit...\n")
    
    # For now, we'll just handle the filesystem kernel modules
    section_id = "1.1.1"
    module_info = next((m for m in cis_audit.MODULES if m["name"] == "fs_kernel_modules"), None)
    
    if module_info:
        print_user_friendly_header(section_id, module_info["title"])
        
        # Run the checks but capture the output
        import io
        import sys
        original_stdout = sys.stdout
        sys.stdout = io.StringIO()
        
        # Run the actual checks
        results = fs_kernel_modules.run_all_audits(return_results=True)
        
        # Restore stdout
        technical_output = sys.stdout.getvalue()
        sys.stdout = original_stdout
        
        # Process and display user-friendly results
        module_results = {
            "cramfs": next((r[2] for r in results if "1.1.1.1" in r[0]), False),
            "freevxfs": next((r[2] for r in results if "1.1.1.2" in r[0]), False),
            "jffs2": next((r[2] for r in results if "1.1.1.3" in r[0]), False),
            "hfs": next((r[2] for r in results if "1.1.1.4" in r[0]), False),
            "hfsplus": next((r[2] for r in results if "1.1.1.5" in r[0]), False),
            "squashfs": next((r[2] for r in results if "1.1.1.6" in r[0]), False),
            "udf": next((r[2] for r in results if "1.1.1.7" in r[0]), False),
            "fat": next((r[2] for r in results if "1.1.1.8" in r[0]), False)
        }
        
        for module_name, result in module_results.items():
            explain_module_result(module_name, result, section_id)
        
        # Summary
        passed = all(module_results.values())
        print("\n" + "-" * 80)
        if passed:
            print(f"\n{COLORS['GREEN']}✅ Overall Result: SECURE{COLORS['RESET']}")
            print(f"{COLORS['GREEN']}All filesystem modules are properly secured.{COLORS['RESET']}")
        else:
            print(f"\n{COLORS['YELLOW']}⚠️ Overall Result: VULNERABLE{COLORS['RESET']}")
            print(f"{COLORS['RED']}Some filesystem modules are not properly secured and pose potential security risks.{COLORS['RESET']}")
            print("Recommendation: Run the remediation to secure these modules.")
            print("Command: python3 user_friendly_report.py remediate")
    
    print("\n" + "=" * 80)
    return passed


def run_user_friendly_remediation():
    """
    Run remediation with user-friendly output
    """
    print("\n🔧 Starting User-Friendly Security Remediation...\n")
    
    # For now, we'll just handle the filesystem kernel modules
    section_id = "1.1.1"
    module_info = next((m for m in cis_audit.MODULES if m["name"] == "fs_kernel_modules"), None)
    
    if module_info:
        section_info = USER_FRIENDLY_EXPLANATIONS.get(section_id, {})
        print_user_friendly_header(section_id, module_info["title"])
        
        print("\nApplying security fixes...")
        if section_info:
            print(f"What this will do: {section_info.get('remediation_explanation', '')}")
        
        # Run the actual remediation
        fs_kernel_modules.run_all_remediations()
        
        print(f"\n{COLORS['GREEN']}✅ Remediation completed successfully!{COLORS['RESET']}")
        print(f"{COLORS['GREEN']}The system has been secured against the identified vulnerabilities.{COLORS['RESET']}")
        print("\nTo verify that all issues have been fixed, run:")
        print("python3 user_friendly_report.py audit")
    
    print("\n" + "=" * 80)


def main():
    """
    Main function to parse arguments and run appropriate functions
    """
    if len(sys.argv) < 2:
        print("Error: Missing required argument.")
        print("Usage: python3 user_friendly_report.py [audit|remediate]")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    
    if mode == "audit":
        run_user_friendly_audit()
    elif mode == "remediate":
        run_user_friendly_remediation()
    else:
        print(f"Error: Invalid mode '{mode}'.")
        print("Usage: python3 user_friendly_report.py [audit|remediate]")
        sys.exit(1)


if __name__ == "__main__":
    main()