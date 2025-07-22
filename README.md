# Ubuntu Linux CIS Benchmark Audit Tools

This repository contains Python-based audit tools for Ubuntu 22.04 LTS that implement checks based on the CIS (Center for Internet Security) Benchmarks.

## Available Audit Tools

### 1. Filesystem Configuration Audit (CIS Section 1.1)

The `cis_filesystem_audit.py` script checks compliance with CIS Benchmark Section 1.1 - Filesystem Configuration, including:

- 1.1.1 Configure Filesystem Kernel Modules
- 1.1.2 Configure /tmp
- 1.1.2.2 Configure /dev/shm
- 1.1.2.3 Configure /home
- 1.1.2.4 Configure /var
- 1.1.2.5 Configure /var/tmp
- 1.1.2.6 Configure /var/log
- 1.1.2.7 Configure /var/log/audit

### 2. Services Audit (CIS Section 2)

The `cis_services_audit.py` script checks compliance with CIS Benchmark Section 2 - Services, including:

- 2.1 Check unnecessary services are not installed
- 2.2 Check time synchronization is enabled

## Usage

### Running the Filesystem Audit

```bash
# Run with terminal output
sudo python3 cis_filesystem_audit.py

# Run with JSON output
sudo python3 cis_filesystem_audit.py --json
```

### Running the Services Audit

```bash
# Run with terminal output
sudo python3 cis_services_audit.py

# Run with JSON output
sudo python3 cis_services_audit.py --json
```

## Output Format

### Terminal Output

The terminal output provides a human-readable format with PASS/FAIL status for each check, along with a description of why the check passed or failed, and remediation steps for failed checks.

Example:
```
Ubuntu 22.04 LTS CIS Section 1.1 - Filesystem Configuration Audit Report
---------------------------------------------------------------------------
[PASS] 1.1.1.1 Ensure cramfs kernel module is not available: cramfs kernel module is not loaded and is disabled
[FAIL] 1.1.2.1 Ensure /tmp is a separate partition: /tmp is not on a separate partition. Remediation: Create a separate partition for /tmp during system installation or resize existing partitions.
```

### JSON Output

The JSON output provides a structured format that can be easily parsed and integrated with other tools or dashboards.

Example:
```json
{
  "results": [
    {
      "check": "1.1.1.1 Ensure cramfs kernel module is not available",
      "status": "PASS",
      "message": "cramfs kernel module is not loaded and is disabled",
      "passed": true
    },
    {
      "check": "1.1.2.1 Ensure /tmp is a separate partition",
      "status": "FAIL",
      "message": "/tmp is not on a separate partition. Remediation: Create a separate partition for /tmp during system installation or resize existing partitions.",
      "passed": false
    }
  ]
}
```

## Requirements

- Python 3.6 or higher
- Root/sudo privileges (required for some checks)
- Ubuntu 22.04 LTS

## Extending the Tools

The audit tools are designed to be modular and easy to extend. To add new checks:

1. Create a new function that performs the check and returns a tuple of (passed, message)
2. Add the check to the `checks` list in the `main()` function

## License

MIT