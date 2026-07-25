import argparse
import datetime
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


# ==========================
# Global Settings
# ==========================

SCAN_DIR = Path("scans")
SCAN_DIR.mkdir(exist_ok=True)

PORT_PATTERN = re.compile(r"^[0-9,\-]+$")

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(localhost|"
    r"([a-zA-Z0-9]"
    r"([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"\.)+"
    r"[a-zA-Z]{2,63})$"
)


# ==========================
# Nmap Check
# ==========================

def check_nmap_installed() -> str:
    """
    Checks whether Nmap is installed and available in PATH.
    """
    nmap_path = shutil.which("nmap")

    if not nmap_path:
        print("[ERROR] Nmap is not installed or not added to PATH.")
        print("Install Nmap first and make sure this command works:")
        print("nmap --version")
        sys.exit(1)

    return nmap_path


# ==========================
# Target Validation
# ==========================

def validate_target(target: str, private_only: bool = False) -> str:
    """
    Validates scan target.

    Allowed:
    - Private IPv4: 192.168.1.10
    - Public IPv4: 8.8.8.8
    - CIDR range: 192.168.1.0/24
    - Domain: example.com
    - Localhost: localhost

    Rejected:
    - http://example.com
    - https://example.com/path
    - command injection strings
    - invalid IPs/domains
    - IPv6 targets

    private_only=True blocks public IPs and domains.
    """

    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    # Reject URLs and paths
    if "://" in target or "/" in target and not is_cidr_like(target):
        raise ValueError(
            "Enter only IP, CIDR, or domain. Do not use http://, https://, or URL paths."
        )

    # Try single IP address first
    try:
        ip = ipaddress.ip_address(target)

        if ip.version != 4:
            raise ValueError("Only IPv4 targets are supported.")

        if private_only:
            allowed = ip.is_private or ip.is_loopback or ip.is_link_local
            if not allowed:
                raise ValueError("Public IP blocked because --private-only is enabled.")

        return str(ip)

    except ValueError:
        pass

    # Try CIDR/network
    try:
        network = ipaddress.ip_network(target, strict=False)

        if network.version != 4:
            raise ValueError("Only IPv4 CIDR ranges are supported.")

        if private_only:
            allowed = network.is_private or network.is_loopback or network.is_link_local
            if not allowed:
                raise ValueError("Public CIDR blocked because --private-only is enabled.")

        # Prevent accidental huge scans
        if network.prefixlen < 24:
            raise ValueError(
                "CIDR range is too large. Use /24 or smaller, for example 192.168.1.0/24."
            )

        return str(network)

    except ValueError as network_error:
        # Continue to domain validation only if this was simply not a network
        if "CIDR range is too large" in str(network_error):
            raise network_error
        if "Only IPv4" in str(network_error):
            raise network_error
        if "blocked" in str(network_error):
            raise network_error

    # Try domain
    if DOMAIN_PATTERN.match(target):
        if private_only and target.lower() != "localhost":
            raise ValueError("Domain scanning blocked because --private-only is enabled.")

        return target.lower()

    raise ValueError(
        "Invalid target. Use a valid IPv4, CIDR, or domain, for example: "
        "192.168.1.10, 192.168.1.0/24, localhost, or example.com"
    )


def is_cidr_like(value: str) -> bool:
    """
    Checks whether a string looks like CIDR notation.
    Example: 192.168.1.0/24
    """
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", value))


# ==========================
# Port Validation
# ==========================

def validate_ports(ports: str) -> str:
    """
    Validates Nmap port input.

    Allowed examples:
    - -
    - all
    - full
    - 22
    - 80,443
    - 1-1000
    - 21,22,80,443,8000-9000

    '-' / 'all' / 'full' means full TCP port scan using Nmap -p-
    """

    ports = ports.strip().lower()

    if not ports:
        return "-"

    if ports in ["-", "all", "full"]:
        return "-"

    if not PORT_PATTERN.match(ports):
        raise ValueError(
            "Invalid port format. Use examples like: -, all, 22, 80,443, 1-1000"
        )

    parts = ports.split(",")

    for part in parts:
        if not part:
            raise ValueError("Invalid empty port entry.")

        if "-" in part:
            start, end = part.split("-", 1)

            if not start.isdigit() or not end.isdigit():
                raise ValueError("Invalid port range.")

            start = int(start)
            end = int(end)

            if start < 1 or end > 65535 or start > end:
                raise ValueError("Port range must be between 1 and 65535.")

        else:
            if not part.isdigit():
                raise ValueError("Invalid port number.")

            port = int(part)

            if port < 1 or port > 65535:
                raise ValueError("Port must be between 1 and 65535.")

    return ports


# ==========================
# File Name Handling
# ==========================

def generate_scan_name(target: str) -> str:
    """
    Creates a safe output filename.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    safe_target = (
        target.replace("/", "_")
        .replace(".", "-")
        .replace(":", "-")
        .replace("\\", "_")
    )

    safe_target = re.sub(r"[^a-zA-Z0-9_\-]", "_", safe_target)

    return f"scan_{safe_target}_{timestamp}"


# ==========================
# Nmap Scan Runner
# ==========================

def run_nmap_scan(
    target: str,
    ports: str,
    private_only: bool = False,
    timeout: int = 3600
) -> dict:
    """
    Runs Nmap scan with fixed project options:

    -p-  : Full TCP port scan when ports='-'
    -p   : Custom ports when specific ports are supplied
    -sV  : Service/version detection
    -O   : OS detection
    -A   : Aggressive scan mode
    -oA  : Save output in .nmap, .xml, and .gnmap formats
    """

    nmap_path = check_nmap_installed()

    validated_target = validate_target(target, private_only=private_only)
    validated_ports = validate_ports(ports)

    scan_name = generate_scan_name(validated_target)
    output_prefix = SCAN_DIR / scan_name

    if validated_ports == "-":
        port_args = ["-p-"]
        display_ports = "all TCP ports"
    else:
        port_args = ["-p", validated_ports]
        display_ports = validated_ports

    command = [
        nmap_path,
        *port_args,
        "-sV",
        "-O",
        "-A",
        "-oA", str(output_prefix),
        validated_target
    ]

    print("\n[INFO] Starting authorized Nmap scan...")
    print(f"[INFO] Target: {validated_target}")
    print(f"[INFO] Ports : {display_ports}")
    print("[INFO] Command:")
    print(" ".join(command))
    print()

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Scan timed out after {timeout} seconds.")

    if result.returncode != 0:
        print("[NMAP STDERR]")
        print(result.stderr)
        raise RuntimeError("Nmap scan failed.")

    xml_file = f"{output_prefix}.xml"
    normal_file = f"{output_prefix}.nmap"
    grepable_file = f"{output_prefix}.gnmap"

    if not Path(xml_file).exists():
        raise RuntimeError("Nmap XML output file was not created.")

    summary = parse_nmap_xml(xml_file)

    json_file = f"{output_prefix}.json"

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)

    return {
        "target": validated_target,
        "ports": display_ports,
        "xml_file": xml_file,
        "normal_file": normal_file,
        "grepable_file": grepable_file,
        "json_file": json_file,
        "summary": summary
    }


# ==========================
# XML Parser
# ==========================

def parse_nmap_xml(xml_file: str) -> list:
    """
    Parses Nmap XML output and extracts:
    - IP address
    - MAC address
    - hostname
    - host status
    - OS guess
    - open ports
    - service name
    - product
    - version
    - extra info
    - CPE
    - NSE script output
    """

    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts_data = []

    for host in root.findall("host"):
        host_info = {
            "ip_address": None,
            "mac_address": None,
            "hostname": None,
            "status": None,
            "os_guess": None,
            "ports": [],
            "host_scripts": []
        }

        status = host.find("status")
        if status is not None:
            host_info["status"] = status.get("state")

        for address in host.findall("address"):
            addr_type = address.get("addrtype")
            addr = address.get("addr")

            if addr_type == "ipv4":
                host_info["ip_address"] = addr
            elif addr_type == "mac":
                host_info["mac_address"] = addr

        hostnames = host.find("hostnames")
        if hostnames is not None:
            hostname_tag = hostnames.find("hostname")
            if hostname_tag is not None:
                host_info["hostname"] = hostname_tag.get("name")

        os_tag = host.find("os")
        if os_tag is not None:
            os_match = os_tag.find("osmatch")
            if os_match is not None:
                host_info["os_guess"] = {
                    "name": os_match.get("name"),
                    "accuracy": os_match.get("accuracy")
                }

        # Host-level scripts from -A
        hostscript_tag = host.find("hostscript")
        if hostscript_tag is not None:
            for script in hostscript_tag.findall("script"):
                host_info["host_scripts"].append({
                    "id": script.get("id"),
                    "output": script.get("output")
                })

        ports_tag = host.find("ports")
        if ports_tag is not None:
            for port in ports_tag.findall("port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")

                state_tag = port.find("state")
                service_tag = port.find("service")

                state = state_tag.get("state") if state_tag is not None else "unknown"

                service_name = None
                product = None
                version = None
                extrainfo = None
                tunnel = None
                cpe_list = []

                if service_tag is not None:
                    service_name = service_tag.get("name")
                    product = service_tag.get("product")
                    version = service_tag.get("version")
                    extrainfo = service_tag.get("extrainfo")
                    tunnel = service_tag.get("tunnel")

                    for cpe in service_tag.findall("cpe"):
                        if cpe.text:
                            cpe_list.append(cpe.text)

                port_scripts = []
                for script in port.findall("script"):
                    port_scripts.append({
                        "id": script.get("id"),
                        "output": script.get("output")
                    })

                if state == "open":
                    host_info["ports"].append({
                        "port": int(port_id),
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "extra_info": extrainfo,
                        "tunnel": tunnel,
                        "cpe": cpe_list,
                        "scripts": port_scripts
                    })

        hosts_data.append(host_info)

    return hosts_data


# ==========================
# Output Printer
# ==========================

def print_summary(scan_result: dict):
    """
    Prints clean scan summary.
    """

    print("\n========== SCAN COMPLETED ==========")
    print(f"Target        : {scan_result['target']}")
    print(f"Ports         : {scan_result['ports']}")
    print(f"XML Output    : {scan_result['xml_file']}")
    print(f"Normal Output : {scan_result['normal_file']}")
    print(f"Grep Output   : {scan_result['grepable_file']}")
    print(f"JSON Output   : {scan_result['json_file']}")
    print("====================================\n")

    for host in scan_result["summary"]:
        print(f"Host: {host['ip_address']}")
        print(f"Status: {host['status']}")

        if host["hostname"]:
            print(f"Hostname: {host['hostname']}")

        if host["mac_address"]:
            print(f"MAC: {host['mac_address']}")

        if host["os_guess"]:
            print(
                f"OS Guess: {host['os_guess']['name']} "
                f"({host['os_guess']['accuracy']}% accuracy)"
            )

        print("Open Ports:")

        if not host["ports"]:
            print("  No open ports found.")
        else:
            for port in host["ports"]:
                service_line = f"  {port['port']}/{port['protocol']} - {port['service']}"

                if port["product"]:
                    service_line += f" - {port['product']}"

                if port["version"]:
                    service_line += f" {port['version']}"

                if port["extra_info"]:
                    service_line += f" ({port['extra_info']})"

                if port["tunnel"]:
                    service_line += f" [{port['tunnel']}]"

                print(service_line)

                if port["cpe"]:
                    for cpe in port["cpe"]:
                        print(f"      CPE: {cpe}")

                if port["scripts"]:
                    for script in port["scripts"]:
                        print(f"      Script: {script['id']}")

        if host["host_scripts"]:
            print("Host Scripts:")
            for script in host["host_scripts"]:
                print(f"  {script['id']}")

        print("-" * 50)


# ==========================
# Main Function
# ==========================

def main():
    parser = argparse.ArgumentParser(
        description="Python Nmap scanner for Centralized Vulnerability Detection project."
    )

    parser.add_argument(
        "-t",
        "--target",
        help="Target IP, CIDR, domain, or localhost. Example: 192.168.1.10, 192.168.1.0/24, example.com"
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="-",
        help="Ports to scan. Use '-' or 'all' for full scan using -p-. Default: full scan."
    )

    parser.add_argument(
        "--private-only",
        action="store_true",
        help="Block public IPs and domains. Allows only private/local lab targets."
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="Scan timeout in seconds. Default: 3600 seconds."
    )

    args = parser.parse_args()

    target = args.target

    if not target:
        target = input("Enter target IP/CIDR/domain: ").strip()

    try:
        scan_result = run_nmap_scan(
            target=target,
            ports=args.ports,
            private_only=args.private_only,
            timeout=args.timeout
        )

        print_summary(scan_result)

    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()