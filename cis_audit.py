#!/usr/bin/env python3
import argparse
import importlib
import sys
import json

# Import the audit modules
try:
    import cis_filesystem_audit
    import cis_services_audit
except ImportError as e:
    print(f"Error importing audit modules: {e}")
    print("Make sure you're running this script from the correct directory.")
    sys.exit(1)

def list_available_checks():
    """List all available checks from all audit modules"""
    all_checks = []
    
    # Get checks from filesystem audit
    for name, _ in cis_filesystem_audit.checks:
        all_checks.append((name, "cis_filesystem_audit"))
    
    # Get checks from services audit
    for name, _ in cis_services_audit.checks:
        all_checks.append((name, "cis_services_audit"))
    
    return all_checks

def run_specific_check(check_id, json_output=False):
    """Run a specific check by its ID"""
    all_checks = list_available_checks()
    
    # Find the check with the matching ID
    for name, module_name in all_checks:
        if check_id in name:
            # Import the module dynamically
            module = importlib.import_module(module_name)
            
            # Find the function for this check
            for check_name, check_func in module.checks:
                if check_id in check_name:
                    # Run the check
                    passed, msg = check_func()
                    status = "PASS" if passed else "FAIL"
                    
                    if json_output:
                        result = {
                            "check": check_name,
                            "status": status,
                            "message": msg,
                            "passed": passed
                        }
                        print(json.dumps(result, indent=2))
                    else:
                        print(f"[{status}] {check_name}: {msg}")
                    return True
    
    print(f"Check with ID '{check_id}' not found.")
    return False

def run_section(section, json_output=False):
    """Run all checks in a specific section"""
    all_checks = list_available_checks()
    results = []
    found = False
    
    for name, module_name in all_checks:
        if name.startswith(section):
            found = True
            # Import the module dynamically
            module = importlib.import_module(module_name)
            
            # Find the function for this check
            for check_name, check_func in module.checks:
                if check_name.startswith(section):
                    # Run the check
                    passed, msg = check_func()
                    status = "PASS" if passed else "FAIL"
                    
                    if json_output:
                        results.append({
                            "check": check_name,
                            "status": status,
                            "message": msg,
                            "passed": passed
                        })
                    else:
                        print(f"[{status}] {check_name}: {msg}")
    
    if json_output and results:
        print(json.dumps({"results": results}, indent=2))
    
    if not found:
        print(f"Section '{section}' not found.")
        return False
    
    return True

def main():
    parser = argparse.ArgumentParser(description='CIS Benchmark Audit Tool for Ubuntu 22.04 LTS')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('--list', action='store_true', help='List all available checks')
    parser.add_argument('--check', type=str, help='Run a specific check by ID (e.g., 1.1.1.1)')
    parser.add_argument('--section', type=str, help='Run all checks in a section (e.g., 1.1.1)')
    args = parser.parse_args()
    
    if args.list:
        print("Available checks:")
        for name, module in list_available_checks():
            print(f"  {name} [{module}]")
        return
    
    if args.check:
        run_specific_check(args.check, args.json)
        return
    
    if args.section:
        run_section(args.section, args.json)
        return
    
    # If no specific options, run all checks
    print("Running all checks...")
    print("\nFilesystem Configuration Audit:")
    print("-" * 40)
    cis_filesystem_audit.main()
    
    print("\nServices Audit:")
    print("-" * 40)
    cis_services_audit.main()

if __name__ == "__main__":
    main()