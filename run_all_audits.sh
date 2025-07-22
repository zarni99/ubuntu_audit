#!/bin/bash

# Run all CIS benchmark audits for Ubuntu 22.04 LTS

echo "Running CIS Benchmark Audits for Ubuntu 22.04 LTS"
echo "=================================================="
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to run an audit and save results
run_audit() {
    local script=$1
    local name=$2
    local output_file="${SCRIPT_DIR}/results_$(basename "$script" .py).txt"
    local json_file="${SCRIPT_DIR}/results_$(basename "$script" .py).json"
    
    echo "Running $name..."
    python3 "$script" > "$output_file"
    python3 "$script" --json > "$json_file"
    echo "Results saved to $output_file and $json_file"
    echo ""
}

# Run filesystem audit
run_audit "${SCRIPT_DIR}/cis_filesystem_audit.py" "Filesystem Configuration Audit (CIS Section 1.1)"

# Run services audit
run_audit "${SCRIPT_DIR}/cis_services_audit.py" "Services Audit (CIS Section 2)"

echo "All audits completed. Results are saved in the results_*.txt and results_*.json files."

# Summary of failures
echo ""
echo "Summary of Failed Checks:"
echo "========================="
grep -h "\[FAIL\]" "${SCRIPT_DIR}/results_"*.txt

echo ""
echo "Done."