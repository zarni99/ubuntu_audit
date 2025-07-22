#!/usr/bin/env python3
import subprocess
import os
import json
import argparse

# CIS Section 2 - Services Audit for Ubuntu 22.04 LTS

# 2.1 Check unnecessary services are not installed
def check_service_not_installed(service_name):
    """Check if a service is not installed"""
    try:
        result = subprocess.run(['dpkg', '-s', service_name], capture_output=True, text=True)
        if 'Status: install ok installed' in result.stdout:
            return False, f"{service_name} is installed"
        else:
            return True, f"{service_name} is not installed"
    except Exception as e:
        return False, f"Error checking {service_name}: {e}"

# 2.1.1 Check xinetd is not installed
def check_xinetd():
    return check_service_not_installed('xinetd')

# 2.1.2 Check openbsd-inetd is not installed
def check_openbsd_inetd():
    return check_service_not_installed('openbsd-inetd')

# 2.1.3 Check avahi-daemon is not installed
def check_avahi_daemon():
    return check_service_not_installed('avahi-daemon')

# 2.1.4 Check cups is not installed
def check_cups():
    return check_service_not_installed('cups')

# 2.1.5 Check isc-dhcp-server is not installed
def check_dhcp_server():
    return check_service_not_installed('isc-dhcp-server')

# 2.1.6 Check slapd is not installed
def check_slapd():
    return check_service_not_installed('slapd')

# 2.1.7 Check nfs-kernel-server is not installed
def check_nfs_server():
    return check_service_not_installed('nfs-kernel-server')

# 2.1.8 Check bind9 is not installed
def check_bind9():
    return check_service_not_installed('bind9')

# 2.1.9 Check vsftpd is not installed
def check_vsftpd():
    return check_service_not_installed('vsftpd')

# 2.1.10 Check apache2 is not installed
def check_apache2():
    return check_service_not_installed('apache2')

# 2.1.11 Check dovecot is not installed
def check_dovecot():
    return check_service_not_installed('dovecot')

# 2.1.12 Check samba is not installed
def check_samba():
    return check_service_not_installed('samba')

# 2.1.13 Check squid is not installed
def check_squid():
    return check_service_not_installed('squid')

# 2.1.14 Check snmpd is not installed
def check_snmpd():
    return check_service_not_installed('snmpd')

# 2.1.15 Check rsync is not installed
def check_rsync():
    return check_service_not_installed('rsync')

# 2.1.16 Check nis is not installed
def check_nis():
    return check_service_not_installed('nis')

# 2.2 Check time synchronization is enabled
def check_chronyd():
    """Check if chronyd service is enabled and configured"""
    try:
        # Check if chronyd is active
        active_result = subprocess.run(['systemctl', 'is-active', 'chronyd'], capture_output=True, text=True)
        enabled_result = subprocess.run(['systemctl', 'is-enabled', 'chronyd'], capture_output=True, text=True)
        
        # Check if config file exists
        config_exists = os.path.isfile('/etc/chrony/chrony.conf')
        
        if ('active' in active_result.stdout.strip() and 
            'enabled' in enabled_result.stdout.strip() and 
            config_exists):
            return True, "chronyd is active, enabled, and configured"
        else:
            status = []
            if 'active' not in active_result.stdout.strip():
                status.append("not active")
            if 'enabled' not in enabled_result.stdout.strip():
                status.append("not enabled")
            if not config_exists:
                status.append("config file missing")
            return False, f"chronyd is {', '.join(status)}"
    except Exception as e:
        return False, f"Error checking chronyd: {e}"

def check_systemd_timesyncd():
    """Check if systemd-timesyncd service is enabled and active"""
    try:
        active_result = subprocess.run(['systemctl', 'is-active', 'systemd-timesyncd'], capture_output=True, text=True)
        enabled_result = subprocess.run(['systemctl', 'is-enabled', 'systemd-timesyncd'], capture_output=True, text=True)
        
        if ('active' in active_result.stdout.strip() and 
            'enabled' in enabled_result.stdout.strip()):
            return True, "systemd-timesyncd is active and enabled"
        else:
            status = []
            if 'active' not in active_result.stdout.strip():
                status.append("not active")
            if 'enabled' not in enabled_result.stdout.strip():
                status.append("not enabled")
            return False, f"systemd-timesyncd is {', '.join(status)}"
    except Exception as e:
        return False, f"Error checking systemd-timesyncd: {e}"

def check_time_synchronization():
    """Check if either chronyd or systemd-timesyncd is properly configured"""
    chronyd_result = check_chronyd()
    if chronyd_result[0]:
        return True, "Time synchronization via chronyd: " + chronyd_result[1]
    
    timesyncd_result = check_systemd_timesyncd()
    if timesyncd_result[0]:
        return True, "Time synchronization via systemd-timesyncd: " + timesyncd_result[1]
    
    return False, "Neither chronyd nor systemd-timesyncd is properly configured"

# Define the checks list at module level for external access
checks = [
    ("2.1.1 Ensure xinetd is not installed", check_xinetd),
    ("2.1.2 Ensure openbsd-inetd is not installed", check_openbsd_inetd),
    ("2.1.3 Ensure avahi-daemon is not installed", check_avahi_daemon),
    ("2.1.4 Ensure cups is not installed", check_cups),
    ("2.1.5 Ensure isc-dhcp-server is not installed", check_dhcp_server),
    ("2.1.6 Ensure slapd is not installed", check_slapd),
    ("2.1.7 Ensure nfs-kernel-server is not installed", check_nfs_server),
    ("2.1.8 Ensure bind9 is not installed", check_bind9),
    ("2.1.9 Ensure vsftpd is not installed", check_vsftpd),
    ("2.1.10 Ensure apache2 is not installed", check_apache2),
    ("2.1.11 Ensure dovecot is not installed", check_dovecot),
    ("2.1.12 Ensure samba is not installed", check_samba),
    ("2.1.13 Ensure squid is not installed", check_squid),
    ("2.1.14 Ensure snmpd is not installed", check_snmpd),
    ("2.1.15 Ensure rsync is not installed", check_rsync),
    ("2.1.16 Ensure nis is not installed", check_nis),
    ("2.2 Ensure time synchronization is configured", check_time_synchronization),
]

def main():
    parser = argparse.ArgumentParser(description='CIS Section 2 - Services Audit for Ubuntu 22.04 LTS')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    args = parser.parse_args()
    
    results = []
    
    if not args.json:
        print("Ubuntu 22.04 LTS CIS Section 2 - Services Audit Report\n" + "-"*60)
    
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