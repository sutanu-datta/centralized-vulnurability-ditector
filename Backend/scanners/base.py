import re
import shutil
import subprocess
from urllib.parse import urlparse


def tool_exists(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def run_command(command: list[str], timeout: int = 600) -> str:
    tool_name = command[0]

    if not tool_exists(tool_name):
        return (
            f"[CVD] Tool not installed or not in PATH: {tool_name}\n"
            f"[CVD] Command skipped: {' '.join(command)}\n"
        )

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )

        output = result.stdout if result.stdout else result.stderr
        return output if output else "[CVD] Command finished with no output."

    except subprocess.TimeoutExpired:
        return f"[CVD] Command timed out after {timeout} seconds: {' '.join(command)}"

    except Exception as e:
        return f"[CVD] Scanner error: {str(e)}"


def is_cidr(target: str) -> bool:
    return "/" in target


def extract_host(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.hostname or target

    return target.strip().split("/")[0]


def build_web_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target.rstrip("/")

    return f"http://{target.rstrip('/')}"


def validate_target(target: str) -> bool:
    target = target.strip()

    ipv4_pattern = (
        r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
        r"(\/([0-9]|[1-2][0-9]|3[0-2]))?$"
    )

    domain_pattern = r"^(?!:\/\/)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

    url_pattern = (
        r"^https?:\/\/"
        r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"
        r"(:[0-9]{1,5})?"
        r"(\/.*)?$"
    )

    return bool(
        re.match(ipv4_pattern, target)
        or re.match(domain_pattern, target)
        or re.match(url_pattern, target)
    )