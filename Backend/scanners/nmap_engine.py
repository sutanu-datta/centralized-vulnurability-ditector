import re
import shlex
import shutil
import subprocess
from typing import Dict, List, Optional, Any

from normalizer.normalize_findings import normalize_nmap


# -----------------------------
# Nmap Scan Profiles
# -----------------------------
# Use "vuln" or "metasploitable" mode for Metasploitable 2 lab testing.
# Keep shell=False in subprocess to avoid command injection.

SCAN_PROFILES = {
    "quick": [
       "-T2",
        "-sV",
        "-O",
        "--version-all",
    ],

    "normal": [
         "-T3",
        "-sV",
        "-O",
        "--script",
        "default,safe",
    ],

    "web": [
        "-T4",
        "-sV",
        "--script",
        "http-title,http-headers,http-server-header,http-methods,http-enum",
        "-p",
        "80,443,8080,8000,8009,8180,8443",
    ],

    "vuln": [
        "-T4",
        "-sV",
        "-O",
        "--version-all",
        "-p-",
    ],

    "full": [
        "-T5",
        "-sV",
        "-O",
        "--script",
        "default,vuln",
        "-p-",
        "21,22,23,25,53,80,111,139,445,512,513,514,1099,1524,2049,2121,3306,5432,5900,6000,6667,8009,8180",
    ],

    
}


BLOCKED_ARGS = {
    "--script-args",
    "--script-args-file",
    "-iL",
    "--exclude-file",
    "-oA",
    "-oX",
    "-oG",
    "-oN",
    "-oS",
}


def _is_nmap_installed() -> bool:
    return shutil.which("nmap") is not None


def _clean_target(target: str) -> str:
    if not target:
        raise ValueError("Target is required.")

    target = target.strip()

    # Remove protocol if user enters http://IP or https://IP
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)

    # Remove path if user enters IP/path
    target = target.split("/")[0]

    # Allow IPv4, IPv6-ish, hostname, and local lab style targets
    if not re.match(r"^[a-zA-Z0-9.\-_:]+$", target):
        raise ValueError("Invalid target format.")

    return target


def _parse_custom_args(custom_args: Optional[str]) -> List[str]:
    if not custom_args:
        return []

    try:
        args = shlex.split(custom_args)
    except ValueError:
        raise ValueError("Invalid custom Nmap arguments.")

    for arg in args:
        if arg in BLOCKED_ARGS:
            raise ValueError(f"Blocked unsafe/custom output argument: {arg}")

    return args


def _build_command(
    target: str,
    mode: str = "normal",
    custom_args: Optional[str] = None,
) -> List[str]:
    target = _clean_target(target)

    mode = (mode or "normal").lower().strip()

    if mode not in SCAN_PROFILES:
        mode = "normal"

    if custom_args:
        # Custom args override profile args but target is still sanitized.
        args = _parse_custom_args(custom_args)
    else:
        args = SCAN_PROFILES[mode]

    return ["nmap"] + args + [target]


def _extract_open_ports(raw_output: str) -> List[Dict[str, str]]:
    ports = []

    for line in raw_output.splitlines():
        match = re.search(
            r"^(\d+)\/(tcp|udp)\s+open\s+([\w\-\?]+)\s*(.*)",
            line.strip(),
            re.IGNORECASE,
        )

        if match:
            ports.append(
                {
                    "port": match.group(1),
                    "protocol": match.group(2),
                    "service": match.group(3),
                    "version": match.group(4).strip(),
                    "evidence": line.strip(),
                }
            )

    return ports


def run_nmap(
    target: str,
    mode: str = "normal",
    custom_args: Optional[str] = None,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run Nmap scan and return raw + normalized output.

    Parameters:
        target:
            IP/domain to scan.

        mode:
            quick, normal, safe, web, vuln, full, metasploitable

        custom_args:
            Optional editable Nmap arguments from frontend.
            Example: "-sV -O -p 21,22,80,445"

        timeout:
            Optional timeout in seconds.

    Returns:
        Dict containing command, raw output, open ports, normalized findings.
    """

    try:
        clean_target = _clean_target(target)

        if not _is_nmap_installed():
            return {
                "tool": "nmap",
                "engine": "nmap",
                "target": clean_target,
                "status": "skipped",
                "success": False,
                "command": "nmap",
                "output": "[CVD] Tool not installed or not in PATH: nmap",
                "raw_output": "[CVD] Tool not installed or not in PATH: nmap",
                "error": "Nmap is not installed or not available in PATH.",
                "return_code": None,
                "findings": [],
                "open_ports": [],
            }

        command = _build_command(
            target=clean_target,
            mode=mode,
            custom_args=custom_args,
        )

        if timeout is None:
            if mode in ["full", "vuln", "metasploitable"]:
                timeout = 900
            elif mode == "web":
                timeout = 500
            else:
                timeout = 300

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            encoding="utf-8",
            errors="replace",
        )

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        combined_output = stdout

        if stderr.strip():
            combined_output += "\n\n[stderr]\n" + stderr

        open_ports = _extract_open_ports(stdout)

        normalized = normalize_nmap(
            raw_output=stdout,
            target=clean_target,
        )

        findings = normalized.get("findings", [])

        return {
            "tool": "nmap",
            "engine": "nmap",
            "target": clean_target,
            "status": "completed" if result.returncode == 0 else "completed_with_errors",
            "success": result.returncode == 0,
            "mode": mode,
            "command": " ".join(command),
            "output": combined_output,
            "raw_output": combined_output,
            "stdout": stdout,
            "stderr": stderr,
            "return_code": result.returncode,
            "open_ports": open_ports,
            "findings": findings,
            "normalized": normalized,
        }

    except subprocess.TimeoutExpired:
        return {
            "tool": "nmap",
            "engine": "nmap",
            "target": target,
            "status": "timeout",
            "success": False,
            "command": "",
            "output": f"[CVD] Nmap scan timed out after {timeout} seconds.",
            "raw_output": f"[CVD] Nmap scan timed out after {timeout} seconds.",
            "error": "Scan timeout.",
            "return_code": None,
            "findings": [],
            "open_ports": [],
        }

    except Exception as e:
        return {
            "tool": "nmap",
            "engine": "nmap",
            "target": target,
            "status": "error",
            "success": False,
            "command": "",
            "output": f"[CVD] Nmap engine error: {str(e)}",
            "raw_output": f"[CVD] Nmap engine error: {str(e)}",
            "error": str(e),
            "return_code": None,
            "findings": [],
            "open_ports": [],
        }