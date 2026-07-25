def run_zap(target: str, intensity: str, brutality: str) -> dict:
    raw_output = (
        "[CVD] OWASP ZAP engine selected.\n"
        "[CVD] ZAP requires ZAP daemon/API integration.\n"
        "[CVD] Current status: placeholder adapter.\n\n"
        f"Target: {target}\n"
        f"Intensity: {intensity}\n"
        f"Brutality: {brutality}\n"
    )

    return {
        "engine": "zap",
        "raw_output": raw_output,
        "findings": [
            {
                "title": "OWASP ZAP adapter not configured",
                "severity": "info",
                "cve": None,
                "cvss": None,
                "affected_component": "ZAP API",
                "description": "OWASP ZAP is selected but API integration is not configured yet.",
                "remediation": "Run ZAP in daemon mode and configure API access in the backend.",
            }
        ],
    }