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
│   ├── filesystem/        # Filesystem-related audit modules
│   │   ├── __init__.py    # Filesystem module package initialization
│   │   └── partitions.py  # Filesystem partition configuration audit
│   ├── package_management/ # Package management audit modules
│   │   ├── __init__.py     # Package management module initialization
│   │   ├── repositories.py # Package repositories audit
│   │   └── updates.py      # Package updates audit
│   ├── access_control/    # Access control audit modules
│   │   ├── __init__.py    # Access control module initialization
│   │   └── apparmor.py    # AppArmor configuration audit
│   ├── bootloader/        # Bootloader audit modules
│   │   ├── __init__.py    # Bootloader module initialization
│   │   └── configuration.py # Bootloader configuration audit
│   ├── process_hardening/ # Process hardening audit modules
│   │   ├── __init__.py    # Process hardening module initialization
│   │   └── process_restrictions.py # Process restrictions audit
│   └── command_line_warning/ # Command line warning audit modules
│       ├── __init__.py      # Command line warning module initialization
│       └── warning_banners.py # Warning banners audit
└── README.md              # This documentation
```

## Implemented Modules

### Filesystem Kernel Modules Audit

The `modules/kernel/fs_modules.py` module audits and optionally remediates the filesystem kernel modules according to CIS Ubuntu 22.04 LTS Benchmark section 1.1.1.

#### Covered Benchmarks

- 1.1.1.1 Ensure cramfs kernel module is not available
- 1.1.1.2 Ensure freevxfs kernel module is not available
- 1.1.1.3 Ensure jffs2 kernel module is not available
- 1.1.1.4 Ensure hfs kernel module is not available
- 1.1.1.5 Ensure hfsplus kernel module is not available
- 1.1.1.6 Ensure squashfs kernel module is not available
- 1.1.1.7 Ensure udf kernel module is not available
- 1.1.1.8 Ensure FAT kernel module is not available

### Filesystem Partition Configuration Audit

The `modules/filesystem/partitions.py` module audits and optionally remediates the filesystem partition configuration according to CIS Ubuntu 22.04 LTS Benchmark section 1.1.2.

#### Covered Benchmarks

- 1.1.2.1 Ensure /tmp is a separate partition
- 1.1.2.2 Ensure nodev option set on /tmp partition
- 1.1.2.3 Ensure nosuid option set on /tmp partition
- 1.1.2.4 Ensure noexec option set on /tmp partition
- 1.1.2.5 Ensure /dev/shm is a separate partition
- 1.1.2.6 Ensure nodev option set on /dev/shm partition
- 1.1.2.7 Ensure nosuid option set on /dev/shm partition
- 1.1.2.8 Ensure noexec option set on /dev/shm partition

### Package Management Audit

The `modules/package_management/` directory contains modules for auditing package management according to CIS Ubuntu 22.04 LTS Benchmark section 1.2.

#### Covered Benchmarks

- 1.2.1.1 Ensure GPG keys are configured (Manual)
- 1.2.1.2 Ensure package manager repositories are configured (Manual)
- 1.2.2.1 Ensure updates, patches, and additional security software are installed (Manual)

### Access Control Audit

The `modules/access_control/apparmor.py` module audits and optionally remediates AppArmor configuration according to CIS Ubuntu 22.04 LTS Benchmark section 1.3.1.

#### Covered Benchmarks

- 1.3.1.1 Ensure AppArmor is installed (Automated)
- 1.3.1.2 Ensure AppArmor is enabled in the bootloader configuration (Automated)
- 1.3.1.3 Ensure all AppArmor Profiles are in enforce or complain mode (Automated)
- 1.3.1.4 Ensure all AppArmor Profiles are enforcing (Automated)

### Bootloader Configuration Audit

The `modules/bootloader/configuration.py` module audits and optionally remediates bootloader configuration according to CIS Ubuntu 22.04 LTS Benchmark section 1.4.

#### Covered Benchmarks

- 1.4.1 Ensure bootloader password is set (Automated)
- 1.4.2 Ensure access to bootloader config is configured (Automated)

### Process Hardening Audit

The `modules/process_hardening/process_restrictions.py` module audits and optionally remediates process hardening configuration according to CIS Ubuntu 22.04 LTS Benchmark section 1.5.

#### Covered Benchmarks

- 1.5.1 Ensure address space layout randomization (ASLR) is enabled (Automated)
- 1.5.2 Ensure ptrace scope is restricted (Automated)
- 1.5.3 Ensure core dumps are restricted (Automated)
- 1.5.4 Ensure prelink is not installed (Automated)
- 1.5.5 Ensure Automatic Error Reporting is not enabled (Automated)

### Command Line Warning Banners Audit

The `modules/command_line_warning/warning_banners.py` module audits and optionally remediates command line warning banners according to CIS Ubuntu 22.04 LTS Benchmark section 1.6.

#### Covered Benchmarks

- 1.6.1 Ensure message of the day is configured properly (Automated)
- 1.6.2 Ensure local login warning banner is configured properly (Automated)
- 1.6.3 Ensure remote login warning banner is configured properly (Automated)
- 1.6.4 Ensure access to the su command is restricted (Automated)

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
from modules.filesystem import partitions
from modules.package_management import repositories, updates
from modules.access_control import apparmor
from modules.bootloader import configuration
from modules.process_hardening import process_restrictions
from modules.command_line_warning import warning_banners
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
        "name": "filesystem",
        "submodules": [
            {
                "name": "partitions",
                "module": partitions,
                "title": "1.1.2 Filesystem Partition Configuration",
                "description": "Ensure partitions are properly configured"
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
                "description": "Ensure process hardening is properly configured"
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
        "title": "Filesystem Kernel Modules",
        "overview": "These checks ensure that unnecessary and potentially dangerous filesystem kernel modules are disabled.",
        "importance": "Disabling unnecessary filesystem modules reduces the attack surface of the system.",
        "pass_meaning": "The module is properly disabled or blacklisted.",
        "fail_meaning": "The module is not disabled or blacklisted and could be loaded.",
        "remediation_explanation": "The remediation will add the module to the kernel module blacklist.",
        "modules": {
            "cramfs": "A compressed read-only filesystem that is unnecessary for most systems.",
            "freevxfs": "The Veritas filesystem driver, unnecessary for most systems.",
            "jffs2": "The Journaling Flash File System, unnecessary for most systems.",
            "hfs": "The Hierarchical File System, used by older Macs, unnecessary for most systems.",
            "hfsplus": "The Hierarchical File System Plus, used by newer Macs, unnecessary for most systems.",
            "squashfs": "A compressed read-only filesystem, unnecessary for most systems.",
            "udf": "The Universal Disk Format filesystem, unnecessary for most systems.",
            "vfat": "The FAT filesystem, unnecessary for most systems."
        }
    },
    "1.1.2": {
        "title": "Filesystem Partition Configuration",
        "overview": "These checks ensure that filesystem partitions are properly configured with appropriate mount options.",
        "importance": "Properly configured partitions help prevent privilege escalation and other attacks.",
        "pass_meaning": "The partition is properly configured with the required mount options.",
        "fail_meaning": "The partition is not properly configured and may be vulnerable to attacks.",
        "remediation_explanation": "The remediation will update the /etc/fstab file to set the appropriate mount options.",
        "modules": {
            "tmp_partition": "Ensures /tmp is a separate partition.",
            "tmp_nodev": "Ensures the nodev option is set on the /tmp partition.",
            "tmp_nosuid": "Ensures the nosuid option is set on the /tmp partition.",
            "tmp_noexec": "Ensures the noexec option is set on the /tmp partition.",
            "dev_shm_partition": "Ensures /dev/shm is a separate partition.",
            "dev_shm_nodev": "Ensures the nodev option is set on the /dev/shm partition.",
            "dev_shm_nosuid": "Ensures the nosuid option is set on the /dev/shm partition.",
            "dev_shm_noexec": "Ensures the noexec option is set on the /dev/shm partition."
        }
    },
    "1.2.1": {
        "title": "Configure Package Repositories",
        "overview": "These checks ensure that package repositories are properly configured with valid GPG keys.",
        "importance": "Properly configured package repositories help prevent malicious packages from being installed.",
        "pass_meaning": "The package repositories are properly configured with valid GPG keys.",
        "fail_meaning": "The package repositories are not properly configured and may be vulnerable to attacks.",
        "remediation_explanation": "The remediation will update the package repository configuration to use valid GPG keys.",
        "modules": {
            "gpg_keys": "Ensures GPG keys are configured for package repositories.",
            "repositories": "Ensures package manager repositories are properly configured."
        }
    },
    "1.2.2": {
        "title": "Configure Package Updates",
        "overview": "These checks ensure that package updates are properly configured and installed.",
        "importance": "Keeping packages updated helps prevent known vulnerabilities from being exploited.",
        "pass_meaning": "The system is configured to receive and install package updates.",
        "fail_meaning": "The system is not configured to receive and install package updates.",
        "remediation_explanation": "The remediation will update the package update configuration and install available updates.",
        "modules": {
            "updates": "Ensures updates, patches, and additional security software are installed."
        }
    },
    "1.3.1": {
        "title": "Configure AppArmor",
        "overview": "These checks ensure that AppArmor is installed, enabled, and properly configured.",
        "importance": "AppArmor provides mandatory access control, which helps prevent privilege escalation and other attacks.",
        "pass_meaning": "AppArmor is properly installed, enabled, and configured.",
        "fail_meaning": "AppArmor is not properly installed, enabled, or configured.",
        "remediation_explanation": "The remediation will install AppArmor, enable it in the bootloader, and set profiles to enforce mode.",
        "modules": {
            "apparmor_installed": "Ensures AppArmor is installed.",
            "apparmor_enabled": "Ensures AppArmor is enabled in the bootloader configuration.",
            "apparmor_profiles_complain": "Ensures all AppArmor Profiles are in enforce or complain mode.",
            "apparmor_profiles_enforce": "Ensures all AppArmor Profiles are enforcing."
        }
    },
    "1.4": {
        "title": "Configure Bootloader",
        "overview": "These checks ensure that the bootloader is properly configured with a password and restricted access.",
        "importance": "A properly configured bootloader helps prevent unauthorized access to the system during boot.",
        "pass_meaning": "The bootloader is properly configured with a password and restricted access.",
        "fail_meaning": "The bootloader is not properly configured and may be vulnerable to attacks.",
        "remediation_explanation": "The remediation will update the bootloader configuration to set a password and restrict access.",
        "modules": {
            "bootloader_password": "Ensures bootloader password is set.",
            "bootloader_config_access": "Ensures access to bootloader config is configured."
        }
    },
    "1.5": {
        "title": "Configure Additional Process Hardening",
        "overview": "These checks ensure that additional process hardening measures are properly configured.",
        "importance": "Process hardening helps prevent privilege escalation and other attacks.",
        "pass_meaning": "The process hardening measures are properly configured.",
        "fail_meaning": "The process hardening measures are not properly configured and may be vulnerable to attacks.",
        "remediation_explanation": "The remediation will update the process hardening configuration to improve security.",
        "modules": {
            "aslr": "Ensures address space layout randomization (ASLR) is enabled.",
            "ptrace_scope": "Ensures ptrace scope is restricted.",
            "core_dumps": "Ensures core dumps are restricted.",
            "prelink": "Ensures prelink is not installed.",
            "error_reporting": "Ensures Automatic Error Reporting is not enabled."
        }
    },
    "1.6": {
        "title": "Configure Command Line Warning Banners",
        "overview": "These checks ensure that command line warning banners are properly configured.",
        "importance": "Warning banners help inform users about acceptable use policies and legal consequences of misuse.",
        "pass_meaning": "The command line warning banners are properly configured.",
        "fail_meaning": "The command line warning banners are not properly configured.",
        "remediation_explanation": "The remediation will update the command line warning banners to display appropriate messages.",
        "modules": {
            "motd": "Ensures message of the day is configured properly.",
            "local_login": "Ensures local login warning banner is configured properly.",
            "remote_login": "Ensures remote login warning banner is configured properly.",
            "su_access": "Ensures access to the su command is restricted."
        }
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