from scanners.base import run_command, build_web_url, is_cidr
from normalizer.normalize_findings import normalize_nikto


def run_nikto(target: str, intensity: str, brutality: str) -> dict:
    if is_cidr(target):
        raw_output = "[CVD] Nikto skipped. Web scanners require a single host or URL, not CIDR."
        return {
            "engine": "nikto",
            "raw_output": raw_output,
            "findings": [],
        }

    url = build_web_url(target)

    timeout_map = {
        "light": 300,
        "normal": 600,
        "deep": 1200,
        "full": 1800,
    }

    command = ["nikto", "-h", url, "-nointeractive"]

    raw_header = (
        f"[CVD] Engine: Nikto\n"
        f"[CVD] Target: {url}\n"
        f"[CVD] Intensity: {intensity}\n"
        f"[CVD] Brutality: {brutality}\n\n"
    )

    raw_output = raw_header + run_command(
        command,
        timeout=timeout_map.get(intensity, 600)
    )

    findings = normalize_nikto(raw_output)

    return {
        "engine": "nikto",
        "raw_output": raw_output,
        "findings": findings,
    }