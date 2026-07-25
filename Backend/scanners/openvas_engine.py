def run_openvas(target: str, intensity: str, brutality: str) -> dict:
    raw_output = (
        "[CVD] OpenVAS/GVM engine selected.\n"
        "[CVD] OpenVAS requires GVM service/API integration.\n"
        "[CVD] Current status: placeholder adapter.\n\n"
        f"Target: {target}\n"
        f"Intensity: {intensity}\n"
        f"Brutality: {brutality}\n"
    )

    return {
        "engine": "openvas",
        "raw_output": raw_output,
        "findings": [
            {
                "title": "OpenVAS adapter not configured",
                "severity": "info",
                "cve": None,
                "cvss": None,
                "affected_component": "GVM/OpenVAS",
                "description": "OpenVAS is selected but GVM API integration is not configured yet.",
                "remediation": "Install OpenVAS/GVM and connect the backend using GVM API.",
            }
        ],
    }