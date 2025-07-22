# Ubuntu Linux CIS Benchmark Audit Tool

This repository contains tools for auditing and remediating Ubuntu Linux systems according to the CIS (Center for Internet Security) Ubuntu 22.04 LTS Benchmark.

## Main Controller Script

The `cis_audit.py` script acts as the main controller for running all CIS Benchmark audit and remediation modules. It provides a unified interface to run all checks or remediations at once, with options for module selection and output format.

### Usage

#### Audit Mode

To run all audit checks without making any changes to the system:

```bash
sudo python3 cis_audit.py audit
```

To run audit checks for a specific module:

```bash
sudo python3 cis_audit.py audit kernel  # Run all kernel module checks
sudo python3 cis_audit.py audit fs_modules  # Run only filesystem module checks
```

The tool now uses user-friendly output by default. To run audit checks with technical output instead:

```bash
sudo python3 cis_audit.py audit --technical
sudo python3 cis_audit.py audit kernel --technical
```

#### Remediation Mode

To remediate all issues found during the audit:

```bash
sudo python3 cis_audit.py remediate
```

To remediate issues for a specific module:

```bash
sudo python3 cis_audit.py remediate kernel
sudo python3 cis_audit.py remediate fs_modules
```

The tool now uses user-friendly output by default. To remediate with technical output instead:

```bash
sudo python3 cis_audit.py remediate --technical
sudo python3 cis_audit.py remediate kernel --technical
```

### Features

- Centralized controller for all benchmark modules
- Module-specific execution for targeted audits and remediations
- User-friendly output by default with clear explanations (technical output available with --technical flag)
- Consistent interface for running audits and remediations
- Clear section headers and summary output
- Extensible design for adding future modules

## Project Structure

```
/
├── cis_audit.py           # Main controller script
├── modules/               # Directory containing all audit modules
│   ├── __init__.py        # Package initialization
│   ├── kernel/            # Kernel-related audit modules
│   │   ├── __init__.py    # Kernel module package initialization
│   │   └── fs_modules.py  # Filesystem kernel modules audit
│   └── ... (future modules)
└── README.md              # This documentation
```

## Filesystem Kernel Modules Audit

The `modules/kernel/fs_modules.py` module audits and optionally remediates the filesystem kernel modules according to CIS Ubuntu 22.04 LTS Benchmark section 1.1.1.

### Covered Benchmarks

- 1.1.1.1 Ensure cramfs kernel module is not available
- 1.1.1.2 Ensure freevxfs kernel module is not available
- 1.1.1.3 Ensure jffs2 kernel module is not available
- 1.1.1.4 Ensure hfs kernel module is not available
- 1.1.1.5 Ensure hfsplus kernel module is not available
- 1.1.1.6 Ensure squashfs kernel module is not available
- 1.1.1.7 Ensure udf kernel module is not available
- 1.1.1.8 Ensure FAT kernel module is not available

### Features

- Modular design with individual check functions for each benchmark item
- Clear pass/fail status for each check with color coding
- Detailed remediation suggestions
- Option to automatically apply remediation
- Summary report of all checks

### Requirements

- Python 3.6 or higher
- Root privileges (sudo) for remediation
- Ubuntu 22.04 LTS (may work on other versions but not tested)

## Adding More Benchmarks

This repository is designed to be extended with additional benchmark checks. Each benchmark section should be implemented as a separate Python module within the appropriate directory under `modules/`.

### Module Requirements

Each module should implement at least these two functions:

```python
def run_all_audits(return_results=False):
    """
    Run all audit checks for this module
    
    Args:
        return_results: If True, return a list of results instead of just True/False
    
    Returns:
        If return_results is True, returns a list of tuples (benchmark_id, description, result)
        Otherwise, returns True if all checks pass, False otherwise
    """
    # Implementation here
    return True  # or return results list if return_results=True

def run_all_remediations():
    """
    Run all remediation functions for this module
    """
    # Implementation here
    return True  # Return True if all remediations succeed, False otherwise
```

### Adding a Module to the Controller

To add a new module to the main controller, update the `MODULES` list in `cis_audit.py`:

```python
# Import your new module
from modules.kernel import fs_modules
from modules.your_category import your_new_module  # Add this line

# Add your module to the MODULES list
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
        "name": "your_category",
        "submodules": [
            {
                "name": "your_module_name",
                "module": your_new_module,
                "title": "X.Y.Z Your Module Title",
                "description": "Description of what your module checks"
            }
        ]
    },
    # Additional modules...
]
```

### User-Friendly Explanations

To add user-friendly explanations for your new module, update the `USER_FRIENDLY_EXPLANATIONS` dictionary in `cis_audit.py`:

```python
USER_FRIENDLY_EXPLANATIONS = {
    "1.1.1": {
        # Existing explanations...
    },
    "X.Y.Z": {  # Your module's section ID
        "title": "Your Module Title",
        "overview": "Brief explanation of what these checks do.",
        "importance": "Why these checks are important for security.",
        "pass_meaning": "What it means when a check passes.",
        "fail_meaning": "What it means when a check fails.",
        "remediation_explanation": "What the remediation will do.",
        "modules": {
            "item1": "Explanation of item1",
            "item2": "Explanation of item2",
            # Add more items as needed
        }
    }
}
```