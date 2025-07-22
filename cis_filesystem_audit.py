#!/usr/bin/env python3
import subprocess
import os
import json
import argparse

# CIS Section 1.1 - Filesystem Configuration Audit for Ubuntu 22.04 LTS

# Helper functions
def run_command(command):
    """Run a shell command and return the output"""
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=False)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)

def check_kernel_module_not_loaded(module_name):
    """Check if a kernel module is not loaded"""
    returncode, stdout, stderr = run_command(['lsmod'])
    if returncode != 0:
        return False, f"Error checking if {module_name} is loaded: {stderr}"
    
    if module_name in stdout:
        return False, f"{module_name} kernel module is loaded"
    else:
        return True, f"{module_name} kernel module is not loaded"

def check_kernel_module_disabled(module_name):
    """Check if a kernel module is disabled in modprobe config"""
    # Check if module is blacklisted in any of the config files
    config_files = [
        '/etc/modprobe.d/*.conf',
        '/etc/modprobe.conf',
        '/lib/modprobe.d/*.conf'
    ]
    
    for config_pattern in config_files:
        returncode, stdout, stderr = run_command(['grep', '-r', f"^install {module_name} /bin/true", config_pattern])
        if returncode == 0 and stdout.strip():
            return True, f"{module_name} kernel module is disabled in modprobe config"
    
    return False, f"{module_name} kernel module is not disabled in modprobe config"

def check_mount_option(mount_point, option):
    """Check if a mount point has a specific option"""
    returncode, stdout, stderr = run_command(['findmnt', '-n', mount_point])
    if returncode != 0:
        return False, f"Mount point {mount_point} not found"
    
    # Extract options from findmnt output
    options = stdout.split()[3].split(',')
    if option in options:
        return True, f"Mount option '{option}' is set on {mount_point}"
    else:
        return False, f"Mount option '{option}' is not set on {mount_point}"

def check_separate_partition(mount_point):
    """Check if a directory is mounted on a separate partition"""
    returncode, stdout, stderr = run_command(['findmnt', '-n', mount_point])
    if returncode != 0:
        return False, f"{mount_point} is not on a separate partition"
    else:
        return True, f"{mount_point} is on a separate partition"

# 1.1.1 Configure Filesystem Kernel Modules
# 1.1.1.1 Ensure cramfs kernel module is not available
def check_cramfs():
    """Check if cramfs kernel module is not loaded and disabled"""
    loaded_check = check_kernel_module_not_loaded('cramfs')
    disabled_check = check_kernel_module_disabled('cramfs')
    
    if loaded_check[0] and disabled_check[0]:
        return True, "cramfs kernel module is not loaded and is disabled"
    elif not loaded_check[0]:
        return False, loaded_check[1] + ". Remediation: rmmod cramfs && echo 'install cramfs /bin/true' > /etc/modprobe.d/cramfs.conf"
    else:
        return False, disabled_check[1] + ". Remediation: echo 'install cramfs /bin/true' > /etc/modprobe.d/cramfs.conf"

# 1.1.1.2 Ensure freevxfs kernel module is not available
def check_freevxfs():
    """Check if freevxfs kernel module is not loaded and disabled"""
    loaded_check = check_kernel_module_not_loaded('freevxfs')
    disabled_check = check_kernel_module_disabled('freevxfs')
    
    if loaded_check[0] and disabled_check[0]:
        return True, "freevxfs kernel module is not loaded and is disabled"
    elif not loaded_check[0]:
        return False, loaded_check[1] + ". Remediation: rmmod freevxfs && echo 'install freevxfs /bin/true' > /etc/modprobe.d/freevxfs.conf"
    else:
        return False, disabled_check[1] + ". Remediation: echo 'install freevxfs /bin/true' > /etc/modprobe.d/freevxfs.conf"

# 1.1.1.3 Ensure hfs kernel module is not available
def check_hfs():
    """Check if hfs kernel module is not loaded and disabled"""
    loaded_check = check_kernel_module_not_loaded('hfs')
    disabled_check = check_kernel_module_disabled('hfs')
    
    if loaded_check[0] and disabled_check[0]:
        return True, "hfs kernel module is not loaded and is disabled"
    elif not loaded_check[0]:
        return False, loaded_check[1] + ". Remediation: rmmod hfs && echo 'install hfs /bin/true' > /etc/modprobe.d/hfs.conf"
    else:
        return False, disabled_check[1] + ". Remediation: echo 'install hfs /bin/true' > /etc/modprobe.d/hfs.conf"

# 1.1.1.4 Ensure hfsplus kernel module is not available
def check_hfsplus():
    """Check if hfsplus kernel module is not loaded and disabled"""
    loaded_check = check_kernel_module_not_loaded('hfsplus')
    disabled_check = check_kernel_module_disabled('hfsplus')
    
    if loaded_check[0] and disabled_check[0]:
        return True, "hfsplus kernel module is not loaded and is disabled"
    elif not loaded_check[0]:
        return False, loaded_check[1] + ". Remediation: rmmod hfsplus && echo 'install hfsplus /bin/true' > /etc/modprobe.d/hfsplus.conf"
    else:
        return False, disabled_check[1] + ". Remediation: echo 'install hfsplus /bin/true' > /etc/modprobe.d/hfsplus.conf"

# 1.1.1.5 Ensure jffs2 kernel module is not available
def check_jffs2():
    """Check if jffs2 kernel module is not loaded and disabled"""
    loaded_check = check_kernel_module_not_loaded('jffs2')
    disabled_check = check_kernel_module_disabled('jffs2')
    
    if loaded_check[0] and disabled_check[0]:
        return True, "jffs2 kernel module is not loaded and is disabled"
    elif not loaded_check[0]:
        return False, loaded_check[1] + ". Remediation: rmmod jffs2 && echo 'install jffs2 /bin/true' > /etc/modprobe.d/jffs2.conf"
    else:
        return False, disabled_check[1] + ". Remediation: echo 'install jffs2 /bin/true' > /etc/modprobe.d/jffs2.conf"

# 1.1.1.6 Ensure squashfs kernel module is not available
def check_squashfs():
    """Check if squashfs kernel module is not loaded and disabled"""
    loaded_check = check_kernel_module_not_loaded('squashfs')
    disabled_check = check_kernel_module_disabled('squashfs')
    
    if loaded_check[0] and disabled_check[0]:
        return True, "squashfs kernel module is not loaded and is disabled"
    elif not loaded_check[0]:
        return False, loaded_check[1] + ". Remediation: rmmod squashfs && echo 'install squashfs /bin/true' > /etc/modprobe.d/squashfs.conf"
    else:
        return False, disabled_check[1] + ". Remediation: echo 'install squashfs /bin/true' > /etc/modprobe.d/squashfs.conf"

# 1.1.1.7 Ensure udf kernel module is not available
def check_udf():
    """Check if udf kernel module is not loaded and disabled"""
    loaded_check = check_kernel_module_not_loaded('udf')
    disabled_check = check_kernel_module_disabled('udf')
    
    if loaded_check[0] and disabled_check[0]:
        return True, "udf kernel module is not loaded and is disabled"
    elif not loaded_check[0]:
        return False, loaded_check[1] + ". Remediation: rmmod udf && echo 'install udf /bin/true' > /etc/modprobe.d/udf.conf"
    else:
        return False, disabled_check[1] + ". Remediation: echo 'install udf /bin/true' > /etc/modprobe.d/udf.conf"

# 1.1.1.8 Ensure usb-storage kernel module is not available
def check_usb_storage():
    """Check if usb-storage kernel module is not loaded and disabled"""
    loaded_check = check_kernel_module_not_loaded('usb-storage')
    disabled_check = check_kernel_module_disabled('usb-storage')
    
    if loaded_check[0] and disabled_check[0]:
        return True, "usb-storage kernel module is not loaded and is disabled"
    elif not loaded_check[0]:
        return False, loaded_check[1] + ". Remediation: rmmod usb-storage && echo 'install usb-storage /bin/true' > /etc/modprobe.d/usb-storage.conf"
    else:
        return False, disabled_check[1] + ". Remediation: echo 'install usb-storage /bin/true' > /etc/modprobe.d/usb-storage.conf"

# 1.1.2 Configure /tmp
# 1.1.2.1 Ensure /tmp is a separate partition
def check_tmp_partition():
    """Check if /tmp is on a separate partition"""
    result = check_separate_partition('/tmp')
    if not result[0]:
        return False, result[1] + ". Remediation: Create a separate partition for /tmp during system installation or resize existing partitions to create space for /tmp."
    return True, result[1]

# 1.1.2.2 Ensure nodev option set on /tmp partition
def check_tmp_nodev():
    """Check if nodev option is set on /tmp partition"""
    result = check_mount_option('/tmp', 'nodev')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nodev' to the mount options for /tmp in /etc/fstab."
    return True, result[1]

# 1.1.2.3 Ensure noexec option set on /tmp partition
def check_tmp_noexec():
    """Check if noexec option is set on /tmp partition"""
    result = check_mount_option('/tmp', 'noexec')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'noexec' to the mount options for /tmp in /etc/fstab."
    return True, result[1]

# 1.1.2.4 Ensure nosuid option set on /tmp partition
def check_tmp_nosuid():
    """Check if nosuid option is set on /tmp partition"""
    result = check_mount_option('/tmp', 'nosuid')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nosuid' to the mount options for /tmp in /etc/fstab."
    return True, result[1]

# 1.1.2.2 Configure /dev/shm
# 1.1.2.2.1 Ensure /dev/shm is a separate partition
def check_dev_shm_partition():
    """Check if /dev/shm is properly mounted"""
    result = check_separate_partition('/dev/shm')
    if not result[0]:
        return False, result[1] + ". Remediation: Add an entry for /dev/shm in /etc/fstab: 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0'"
    return True, result[1]

# 1.1.2.2.2 Ensure nodev option set on /dev/shm partition
def check_dev_shm_nodev():
    """Check if nodev option is set on /dev/shm partition"""
    result = check_mount_option('/dev/shm', 'nodev')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nodev' to the mount options for /dev/shm in /etc/fstab."
    return True, result[1]

# 1.1.2.2.3 Ensure noexec option set on /dev/shm partition
def check_dev_shm_noexec():
    """Check if noexec option is set on /dev/shm partition"""
    result = check_mount_option('/dev/shm', 'noexec')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'noexec' to the mount options for /dev/shm in /etc/fstab."
    return True, result[1]

# 1.1.2.2.4 Ensure nosuid option set on /dev/shm partition
def check_dev_shm_nosuid():
    """Check if nosuid option is set on /dev/shm partition"""
    result = check_mount_option('/dev/shm', 'nosuid')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nosuid' to the mount options for /dev/shm in /etc/fstab."
    return True, result[1]

# 1.1.2.3 Configure /home
# 1.1.2.3.1 Ensure separate partition exists for /home
def check_home_partition():
    """Check if /home is on a separate partition"""
    result = check_separate_partition('/home')
    if not result[0]:
        return False, result[1] + ". Remediation: Create a separate partition for /home during system installation or resize existing partitions."
    return True, result[1]

# 1.1.2.3.2 Ensure nodev option set on /home partition
def check_home_nodev():
    """Check if nodev option is set on /home partition"""
    result = check_mount_option('/home', 'nodev')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nodev' to the mount options for /home in /etc/fstab."
    return True, result[1]

# 1.1.2.3.3 Ensure nosuid option set on /home partition
def check_home_nosuid():
    """Check if nosuid option is set on /home partition"""
    result = check_mount_option('/home', 'nosuid')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nosuid' to the mount options for /home in /etc/fstab."
    return True, result[1]

# 1.1.2.4 Configure /var
# 1.1.2.4.1 Ensure separate partition exists for /var
def check_var_partition():
    """Check if /var is on a separate partition"""
    result = check_separate_partition('/var')
    if not result[0]:
        return False, result[1] + ". Remediation: Create a separate partition for /var during system installation or resize existing partitions."
    return True, result[1]

# 1.1.2.4.2 Ensure nodev option set on /var partition
def check_var_nodev():
    """Check if nodev option is set on /var partition"""
    result = check_mount_option('/var', 'nodev')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nodev' to the mount options for /var in /etc/fstab."
    return True, result[1]

# 1.1.2.4.3 Ensure nosuid option set on /var partition
def check_var_nosuid():
    """Check if nosuid option is set on /var partition"""
    result = check_mount_option('/var', 'nosuid')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nosuid' to the mount options for /var in /etc/fstab."
    return True, result[1]

# 1.1.2.5 Configure /var/tmp
# 1.1.2.5.1 Ensure separate partition exists for /var/tmp
def check_var_tmp_partition():
    """Check if /var/tmp is on a separate partition"""
    result = check_separate_partition('/var/tmp')
    if not result[0]:
        return False, result[1] + ". Remediation: Create a separate partition for /var/tmp during system installation or resize existing partitions."
    return True, result[1]

# 1.1.2.5.2 Ensure nodev option set on /var/tmp partition
def check_var_tmp_nodev():
    """Check if nodev option is set on /var/tmp partition"""
    result = check_mount_option('/var/tmp', 'nodev')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nodev' to the mount options for /var/tmp in /etc/fstab."
    return True, result[1]

# 1.1.2.5.3 Ensure nosuid option set on /var/tmp partition
def check_var_tmp_nosuid():
    """Check if nosuid option is set on /var/tmp partition"""
    result = check_mount_option('/var/tmp', 'nosuid')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nosuid' to the mount options for /var/tmp in /etc/fstab."
    return True, result[1]

# 1.1.2.5.4 Ensure noexec option set on /var/tmp partition
def check_var_tmp_noexec():
    """Check if noexec option is set on /var/tmp partition"""
    result = check_mount_option('/var/tmp', 'noexec')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'noexec' to the mount options for /var/tmp in /etc/fstab."
    return True, result[1]

# 1.1.2.6 Configure /var/log
# 1.1.2.6.1 Ensure separate partition exists for /var/log
def check_var_log_partition():
    """Check if /var/log is on a separate partition"""
    result = check_separate_partition('/var/log')
    if not result[0]:
        return False, result[1] + ". Remediation: Create a separate partition for /var/log during system installation or resize existing partitions."
    return True, result[1]

# 1.1.2.6.2 Ensure nodev option set on /var/log partition
def check_var_log_nodev():
    """Check if nodev option is set on /var/log partition"""
    result = check_mount_option('/var/log', 'nodev')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nodev' to the mount options for /var/log in /etc/fstab."
    return True, result[1]

# 1.1.2.6.3 Ensure nosuid option set on /var/log partition
def check_var_log_nosuid():
    """Check if nosuid option is set on /var/log partition"""
    result = check_mount_option('/var/log', 'nosuid')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nosuid' to the mount options for /var/log in /etc/fstab."
    return True, result[1]

# 1.1.2.6.4 Ensure noexec option set on /var/log partition
def check_var_log_noexec():
    """Check if noexec option is set on /var/log partition"""
    result = check_mount_option('/var/log', 'noexec')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'noexec' to the mount options for /var/log in /etc/fstab."
    return True, result[1]

# 1.1.2.7 Configure /var/log/audit
# 1.1.2.7.1 Ensure separate partition exists for /var/log/audit
def check_var_log_audit_partition():
    """Check if /var/log/audit is on a separate partition"""
    result = check_separate_partition('/var/log/audit')
    if not result[0]:
        return False, result[1] + ". Remediation: Create a separate partition for /var/log/audit during system installation or resize existing partitions."
    return True, result[1]

# 1.1.2.7.2 Ensure nodev option set on /var/log/audit partition
def check_var_log_audit_nodev():
    """Check if nodev option is set on /var/log/audit partition"""
    result = check_mount_option('/var/log/audit', 'nodev')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nodev' to the mount options for /var/log/audit in /etc/fstab."
    return True, result[1]

# 1.1.2.7.3 Ensure nosuid option set on /var/log/audit partition
def check_var_log_audit_nosuid():
    """Check if nosuid option is set on /var/log/audit partition"""
    result = check_mount_option('/var/log/audit', 'nosuid')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'nosuid' to the mount options for /var/log/audit in /etc/fstab."
    return True, result[1]

# 1.1.2.7.4 Ensure noexec option set on /var/log/audit partition
def check_var_log_audit_noexec():
    """Check if noexec option is set on /var/log/audit partition"""
    result = check_mount_option('/var/log/audit', 'noexec')
    if not result[0]:
        return False, result[1] + ". Remediation: Add 'noexec' to the mount options for /var/log/audit in /etc/fstab."
    return True, result[1]

# Define the checks list at module level for external access
checks = [
    # 1.1.1 Configure Filesystem Kernel Modules
    ("1.1.1.1 Ensure cramfs kernel module is not available", check_cramfs),
    ("1.1.1.2 Ensure freevxfs kernel module is not available", check_freevxfs),
    ("1.1.1.3 Ensure hfs kernel module is not available", check_hfs),
    ("1.1.1.4 Ensure hfsplus kernel module is not available", check_hfsplus),
    ("1.1.1.5 Ensure jffs2 kernel module is not available", check_jffs2),
    ("1.1.1.6 Ensure squashfs kernel module is not available", check_squashfs),
    ("1.1.1.7 Ensure udf kernel module is not available", check_udf),
    ("1.1.1.8 Ensure usb-storage kernel module is not available", check_usb_storage),
    
    # 1.1.2 Configure /tmp
    ("1.1.2.1 Ensure /tmp is a separate partition", check_tmp_partition),
    ("1.1.2.2 Ensure nodev option set on /tmp partition", check_tmp_nodev),
    ("1.1.2.3 Ensure noexec option set on /tmp partition", check_tmp_noexec),
    ("1.1.2.4 Ensure nosuid option set on /tmp partition", check_tmp_nosuid),
    
    # 1.1.2.2 Configure /dev/shm
    ("1.1.2.2.1 Ensure /dev/shm is a separate partition", check_dev_shm_partition),
    ("1.1.2.2.2 Ensure nodev option set on /dev/shm partition", check_dev_shm_nodev),
    ("1.1.2.2.3 Ensure noexec option set on /dev/shm partition", check_dev_shm_noexec),
    ("1.1.2.2.4 Ensure nosuid option set on /dev/shm partition", check_dev_shm_nosuid),
    
    # 1.1.2.3 Configure /home
    ("1.1.2.3.1 Ensure separate partition exists for /home", check_home_partition),
    ("1.1.2.3.2 Ensure nodev option set on /home partition", check_home_nodev),
    ("1.1.2.3.3 Ensure nosuid option set on /home partition", check_home_nosuid),
    
    # 1.1.2.4 Configure /var
    ("1.1.2.4.1 Ensure separate partition exists for /var", check_var_partition),
    ("1.1.2.4.2 Ensure nodev option set on /var partition", check_var_nodev),
    ("1.1.2.4.3 Ensure nosuid option set on /var partition", check_var_nosuid),
    
    # 1.1.2.5 Configure /var/tmp
    ("1.1.2.5.1 Ensure separate partition exists for /var/tmp", check_var_tmp_partition),
    ("1.1.2.5.2 Ensure nodev option set on /var/tmp partition", check_var_tmp_nodev),
    ("1.1.2.5.3 Ensure nosuid option set on /var/tmp partition", check_var_tmp_nosuid),
    ("1.1.2.5.4 Ensure noexec option set on /var/tmp partition", check_var_tmp_noexec),
    
    # 1.1.2.6 Configure /var/log
    ("1.1.2.6.1 Ensure separate partition exists for /var/log", check_var_log_partition),
    ("1.1.2.6.2 Ensure nodev option set on /var/log partition", check_var_log_nodev),
    ("1.1.2.6.3 Ensure nosuid option set on /var/log partition", check_var_log_nosuid),
    ("1.1.2.6.4 Ensure noexec option set on /var/log partition", check_var_log_noexec),
    
    # 1.1.2.7 Configure /var/log/audit
    ("1.1.2.7.1 Ensure separate partition exists for /var/log/audit", check_var_log_audit_partition),
    ("1.1.2.7.2 Ensure nodev option set on /var/log/audit partition", check_var_log_audit_nodev),
    ("1.1.2.7.3 Ensure nosuid option set on /var/log/audit partition", check_var_log_audit_nosuid),
    ("1.1.2.7.4 Ensure noexec option set on /var/log/audit partition", check_var_log_audit_noexec),
]

def main():
    parser = argparse.ArgumentParser(description='CIS Section 1.1 - Filesystem Configuration Audit for Ubuntu 22.04 LTS')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    args = parser.parse_args()
    
    results = []
    
    if not args.json:
        print("Ubuntu 22.04 LTS CIS Section 1.1 - Filesystem Configuration Audit Report\n" + "-"*75)
    
    for name, func in checks:
        passed, msg = func()
        status = "PASS" if passed else "FAIL"
        
        if args.json:
            results.append({
                "check": name,
                "status": status,
                "message": msg,
                "passed": passed
            })
        else:
            print(f"[{status}] {name}: {msg}")
    
    if args.json:
        print(json.dumps({"results": results}, indent=2))

if __name__ == "__main__":
    main()