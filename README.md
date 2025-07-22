# Ubuntu Linux CIS Benchmark Audit Tool

This repository contains tools for auditing and remediating Ubuntu Linux systems according to the CIS (Center for Internet Security) Ubuntu 22.04 LTS Benchmark.

## Main Controller Script

The `cis_audit.py` script acts as the main controller for running all CIS Benchmark audit and remediation modules. It provides a unified interface to run all checks or remediations at once.

### Usage

#### Audit Mode

To run all audit checks without making any changes to the system:

```bash
sudo python3 cis_audit.py audit
```

#### Remediation Mode

To remediate all issues found during the audit:

```bash
sudo python3 cis_audit.py remediate
```

### Features

- Centralized controller for all benchmark modules
- Consistent interface for running audits and remediations
- Clear section headers and summary output
- Extensible design for adding future modules

## Filesystem Kernel Modules Audit

The `fs_kernel_modules.py` script audits and optionally remediates the filesystem kernel modules according to CIS Ubuntu 22.04 LTS Benchmark section 1.1.1.

### Covered Benchmarks

- 1.1.1.1 Ensure cramfs kernel module is not available
- 1.1.1.2 Ensure freevxfs kernel module is not available
- 1.1.1.3 Ensure jffs2 kernel module is not available
- 1.1.1.4 Ensure hfs kernel module is not available
- 1.1.1.5 Ensure hfsplus kernel module is not available
- 1.1.1.6 Ensure squashfs kernel module is not available
- 1.1.1.7 Ensure udf kernel module is not available
- 1.1.1.8 Ensure FAT kernel module is not available

### Usage

#### Audit Mode

To run the audit without making any changes to the system:

```bash
sudo python3 fs_kernel_modules.py audit
```

#### Remediation Mode

To remediate any issues found during the audit:

```bash
sudo python3 fs_kernel_modules.py remediate
```

### Features

- Modular design with individual check functions for each benchmark item
- Clear pass/fail status for each check
- Detailed remediation suggestions
- Option to automatically apply remediation
- Summary report of all checks

### Requirements

- Python 3.6 or higher
- Root privileges (sudo) for remediation
- Ubuntu 22.04 LTS (may work on other versions but not tested)

## Adding More Benchmarks

This repository is designed to be extended with additional benchmark checks. Each benchmark section should be implemented as a separate Python module with a similar structure to `fs_kernel_modules.py`.

### Module Requirements

Each module should implement at least these two functions:

```python
def run_all_audits():
    """
    Run all audit checks for this module
    """
    # Implementation here
    return True  # Return True if all checks pass, False otherwise

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
import fs_kernel_modules
import your_new_module  # Add this line

# Add your module to the MODULES list
MODULES = [
    {
        "name": "fs_kernel_modules",
        "module": fs_kernel_modules,
        "title": "1.1.1 Filesystem Kernel Modules",
        "description": "Ensure unnecessary filesystem modules are disabled"
    },
    {
        "name": "your_new_module",
        "module": your_new_module,
        "title": "X.Y.Z Your Module Title",
        "description": "Description of what your module checks"
    },
    # Additional modules...
]
```