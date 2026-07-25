def run_nessus(target: str, intensity: str, brutality: str) -> dict:
    raw_output = (
        "[CVD] Nessus engine selected.\n"
        "[CVD] Nessus requires Nessus API integration.\n"
        "[CVD] Current status: placeholder adapter.\n\n"
        f"Target: {target}\n"
        f"Intensity: {intensity}\n"
        f"Brutality: {brutality}\n"
    )

    return {
        "engine": "nessus",
        "raw_output": raw_output,
        "findings": [
            {
                "title": "Nessus adapter not configured",
                "severity": "info",
                "cve": None,
                "cvss": None,
                "affected_component": "Nessus API",
                "description": "Nessus is selected but API integration is not configured yet.",
                "remediation": "Configure Nessus API credentials and scan policy mapping in backend.",
            }
        ],
    }