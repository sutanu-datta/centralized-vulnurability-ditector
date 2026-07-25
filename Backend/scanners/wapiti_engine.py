import os
import shutil
import subprocess
from typing import Dict, Any, Optional

from normalizer.normalize_findings import normalize_wapiti


def _find_wapiti() -> Optional[str]:
    wapiti_path = shutil.which("wapiti")

    if wapiti_path:
        return wapiti_path

    fallback_path = os.path.join(
        os.environ.get("APPDATA", ""),
        "Python",
        "Python312",
        "Scripts",
        "wapiti.exe",
    )

    if os.path.exists(fallback_path):
        return fallback_path

    return None


def _clean_url(target) -> str:
    target = str(target or "").strip()

    if not target:
        raise ValueError("Target is required.")

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    return target


def _safe_int(value, default: int = 900) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def run_wapiti(
    target,
    intensity="safe",
    timeout=900,
    *args,
    **kwargs
) -> Dict[str, Any]:

    try:
        wapiti_bin = _find_wapiti()
        clean_target = _clean_url(target)

        intensity = str(intensity or "safe").lower().strip()
        timeout = _safe_int(timeout, 900)

        if not wapiti_bin:
            return {
                "tool": "wapiti",
                "engine": "wapiti",
                "target": clean_target,
                "status": "skipped",
                "success": False,
                "command": "wapiti",
                "output": "[CVD] Tool not installed or not in PATH: wapiti",
                "raw_output": "[CVD] Tool not installed or not in PATH: wapiti",
                "error": "Wapiti executable not found.",
                "return_code": None,
                "findings": [],
            }

        command = [
            wapiti_bin,
            "-u",
            clean_target,
            "-f",
            "txt",
            "--scope",
            "page",
            "--flush-session",
            "--max-links-per-page",
            "20",
        ]

        if intensity in ["deep", "aggressive"]:
            command = [
                wapiti_bin,
                "-u",
                clean_target,
                "-f",
                "txt",
                "--scope",
                "domain",
                "--flush-session",
            ]

        command = [str(part) for part in command]

        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONLEGACYWINDOWSSTDIO"] = "0"

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            encoding="utf-8",
            errors="replace",
            env=env,
        )

        stdout = str(result.stdout or "")
        stderr = str(result.stderr or "")

        combined_output = stdout

        if stderr.strip():
            combined_output += "\n\n[stderr]\n" + stderr

        normalized = normalize_wapiti(
            raw_output=combined_output,
            target=clean_target,
        )

        return {
            "tool": "wapiti",
            "engine": "wapiti",
            "target": clean_target,
            "status": "completed" if result.returncode == 0 else "completed_with_errors",
            "success": result.returncode == 0,
            "command": " ".join(command),
            "output": combined_output,
            "raw_output": combined_output,
            "stdout": stdout,
            "stderr": stderr,
            "return_code": result.returncode,
            "findings": normalized.get("findings", []),
            "normalized": normalized,
        }

    except subprocess.TimeoutExpired:
        timeout = _safe_int(timeout, 900)

        return {
            "tool": "wapiti",
            "engine": "wapiti",
            "target": str(target),
            "status": "timeout",
            "success": False,
            "command": "",
            "output": f"[CVD] Wapiti scan timed out after {timeout} seconds.",
            "raw_output": f"[CVD] Wapiti scan timed out after {timeout} seconds.",
            "error": "Scan timeout.",
            "return_code": None,
            "findings": [],
        }

    except Exception as e:
        return {
            "tool": "wapiti",
            "engine": "wapiti",
            "target": str(target),
            "status": "error",
            "success": False,
            "command": "",
            "output": f"[CVD] Wapiti engine error: {str(e)}",
            "raw_output": f"[CVD] Wapiti engine error: {str(e)}",
            "error": str(e),
            "return_code": None,
            "findings": [],
        }