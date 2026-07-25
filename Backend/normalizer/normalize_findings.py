import re


def normalize_nmap(raw_output, target=None):
    findings = []

    lines = raw_output.splitlines()

    for line in lines:
        line_lower = line.lower()

        # Generic open port detection
        open_port_match = re.search(r"^(\d+)\/tcp\s+open\s+([\w\-\?]+)\s*(.*)", line, re.I)

        if open_port_match:
            port = open_port_match.group(1)
            service = open_port_match.group(2)
            version = open_port_match.group(3).strip()

            severity = "info"
            title = f"Open {service} service on port {port}/tcp"
            cve = "-"
            remediation = "Verify that this service is required. Restrict access with firewall rules and keep the service updated."

            # Metasploitable 2 known vulnerable service rules

            if "vsftpd 2.3.4" in line_lower:
                severity = "critical"
                title = "vsftpd 2.3.4 backdoor vulnerability detected"
                cve = "CVE-2011-2523"
                remediation = "Remove vsftpd 2.3.4 immediately and upgrade to a patched FTP server version. Restrict FTP exposure."

            elif "unrealircd" in line_lower:
                severity = "critical"
                title = "UnrealIRCd backdoor vulnerability detected"
                cve = "CVE-2010-2075"
                remediation = "Remove the vulnerable UnrealIRCd version and install a verified clean version from trusted source."

            elif "samba" in line_lower and ("3.0.20" in line_lower or "3.x" in line_lower):
                severity = "high"
                title = "Potential vulnerable Samba service detected"
                cve = "CVE-2007-2447"
                remediation = "Upgrade Samba to a supported version. Disable anonymous access and restrict SMB to trusted hosts."

            elif "apache httpd 2.2.8" in line_lower:
                severity = "high"
                title = "Outdated Apache HTTP Server detected"
                cve = "Multiple"
                remediation = "Upgrade Apache to a supported version. Disable risky modules and harden web server configuration."

            elif service.lower() in ["mysql"] and "5.0" in line_lower:
                severity = "high"
                title = "Outdated MySQL service detected"
                cve = "Multiple"
                remediation = "Upgrade MySQL/MariaDB, disable remote root login, enforce strong credentials, and restrict port 3306."

            elif service.lower() in ["postgresql"] or "postgresql" in line_lower:
                severity = "medium"
                title = "PostgreSQL database service exposed"
                cve = "-"
                remediation = "Restrict PostgreSQL access to trusted hosts only and enforce strong authentication."

            elif service.lower() in ["vnc"]:
                severity = "high"
                title = "VNC remote desktop service exposed"
                cve = "-"
                remediation = "Disable VNC if unnecessary. Otherwise restrict by VPN/firewall and enforce strong authentication."

            elif service.lower() in ["nfs"]:
                severity = "medium"
                title = "NFS file sharing service exposed"
                cve = "-"
                remediation = "Restrict NFS exports, disable anonymous access, and limit access to trusted internal hosts."

            elif service.lower() in ["telnet"]:
                severity = "high"
                title = "Insecure Telnet service exposed"
                cve = "-"
                remediation = "Disable Telnet and use SSH instead."

            elif service.lower() in ["ftp"]:
                severity = "medium"
                title = "FTP service exposed"
                cve = "-"
                remediation = "Use SFTP/FTPS instead of plain FTP. Restrict FTP access and disable anonymous login."

            elif port == "1524":
                severity = "critical"
                title = "Metasploitable bind shell service detected"
                cve = "-"
                remediation = "Remove the rogue bind shell service immediately and investigate system compromise."

            elif port in ["512", "513", "514"]:
                severity = "high"
                title = "Insecure r-services detected"
                cve = "-"
                remediation = "Disable rexec/rlogin/rsh services and replace them with SSH."

            findings.append({
                "severity": severity,
                "vulnerability": title,
                "engine": "nmap",
                "component": service,
                "port": port,
                "cve": cve,
                "remediation": remediation,
                "evidence": line
            })

        # Nmap NSE vuln script output detection
        if "cve-" in line_lower:
            cves = re.findall(r"CVE-\d{4}-\d+", line, re.I)
            for detected_cve in cves:
                findings.append({
                    "severity": "high",
                    "vulnerability": f"Nmap NSE detected vulnerability {detected_cve.upper()}",
                    "engine": "nmap",
                    "component": "nmap-script",
                    "port": "-",
                    "cve": detected_cve.upper(),
                    "remediation": "Review the Nmap NSE script result and patch the affected service.",
                    "evidence": line.strip()
                })

    return {
        "tool": "nmap",
        "target": target,
        "findings": findings,
        "raw_output": raw_output
    }


def normalize_nikto(raw_output, target=None):
    findings = []

    for line in raw_output.splitlines():
        line_lower = line.lower()

        if "osvdb" in line_lower or "cve-" in line_lower or "vulnerable" in line_lower:
            findings.append({
                "severity": "medium",
                "vulnerability": line.strip(),
                "engine": "nikto",
                "component": "web",
                "port": "80/443",
                "cve": ", ".join(re.findall(r"CVE-\d{4}-\d+", line, re.I)) or "-",
                "remediation": "Review Nikto finding, patch the web server, remove risky files, and harden configuration.",
                "evidence": line.strip()
            })

    return {
        "tool": "nikto",
        "target": target,
        "findings": findings,
        "raw_output": raw_output
    }


def normalize_wapiti(raw_output, target=None):
    findings = []

    for line in raw_output.splitlines():
        line_lower = line.lower()

        if any(keyword in line_lower for keyword in ["sql injection", "xss", "file disclosure", "command execution", "vulnerability"]):
            findings.append({
                "severity": "high",
                "vulnerability": line.strip(),
                "engine": "wapiti",
                "component": "web",
                "port": "80/443",
                "cve": "-",
                "remediation": "Validate the web vulnerability and fix input validation, output encoding, authentication, or server-side logic.",
                "evidence": line.strip()
            })

    return {
        "tool": "wapiti",
        "target": target,
        "findings": findings,
        "raw_output": raw_output
    }