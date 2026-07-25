import json
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from auth import create_token, get_current_user, hash_password, verify_password
from database import get_conn, init_db, now
from scanners.base import validate_target
from scanners.nmap_engine import run_nmap
from scanners.nikto_engine import run_nikto
from scanners.wapiti_engine import run_wapiti
from scanners.zap_engine import run_zap
from scanners.openvas_engine import run_openvas
from scanners.nessus_engine import run_nessus


app = FastAPI(title="CVD Backend API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


init_db()


ENGINE_RUNNERS = {
    "nmap": run_nmap,
    "nikto": run_nikto,
    "wapiti": run_wapiti,
    "zap": run_zap,
    "openvas": run_openvas,
    "nessus": run_nessus,
}


ESTIMATE_MAP = {
    "nmap": {"light": 1, "normal": 3, "deep": 8, "full": 15},
    "nikto": {"light": 2, "normal": 5, "deep": 10, "full": 15},
    "wapiti": {"light": 3, "normal": 8, "deep": 15, "full": 25},
    "zap": {"light": 5, "normal": 15, "deep": 30, "full": 45},
    "openvas": {"light": 15, "normal": 30, "deep": 60, "full": 90},
    "nessus": {"light": 15, "normal": 30, "deep": 60, "full": 90},
}


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class EngineConfig(BaseModel):
    enabled: bool = False
    intensity: str = "normal"
    brutality: str = "safe"


class MultiScanRequest(BaseModel):
    target: str
    engines: dict[str, EngineConfig]


def calculate_estimate(engines: dict) -> int:
    total = 0

    for engine_name, config in engines.items():
        if not config.enabled:
            continue

        total += ESTIMATE_MAP.get(engine_name, {}).get(config.intensity, 5)

    return total


def severity_counts(scan_id: int) -> dict:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT severity, COUNT(*) as total
        FROM vulnerabilities
        WHERE scan_id = ?
        GROUP BY severity
        """,
        (scan_id,),
    ).fetchall()
    conn.close()

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for row in rows:
        sev = row["severity"].lower()
        if sev in counts:
            counts[sev] = row["total"]

    return counts


def run_scan_job(scan_id: int, target: str, engines: dict):
    conn = get_conn()
    conn.execute(
        "UPDATE scan_jobs SET status = ? WHERE id = ?",
        ("running", scan_id),
    )
    conn.commit()
    conn.close()

    try:
        for engine_name, config in engines.items():
            if not config.get("enabled"):
                continue

            runner = ENGINE_RUNNERS.get(engine_name)

            if not runner:
                continue

            intensity = config.get("intensity", "normal")
            brutality = config.get("brutality", "safe")

            result = runner(target, intensity, brutality)

            conn = get_conn()
            conn.execute(
                """
                INSERT INTO scan_outputs
                (scan_id, engine, raw_output, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    scan_id,
                    result["engine"],
                    result["raw_output"],
                    now(),
                ),
            )

            for item in result.get("findings", []):
                conn.execute(
                    """
                    INSERT INTO vulnerabilities
                    (
                        scan_id,
                        target,
                        engine,
                        title,
                        severity,
                        cve,
                        cvss,
                        affected_component,
                        description,
                        remediation,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        target,
                        result["engine"],
                        item.get("title", "Untitled finding"),
                        item.get("severity", "info"),
                        item.get("cve"),
                        item.get("cvss"),
                        item.get("affected_component"),
                        item.get("description"),
                        item.get("remediation"),
                        now(),
                    ),
                )

            conn.commit()
            conn.close()

        conn = get_conn()
        conn.execute(
            """
            UPDATE scan_jobs
            SET status = ?, completed_at = ?
            WHERE id = ?
            """,
            ("completed", now(), scan_id),
        )
        conn.commit()
        conn.close()

    except Exception as e:
        conn = get_conn()
        conn.execute(
            """
            UPDATE scan_jobs
            SET status = ?, completed_at = ?
            WHERE id = ?
            """,
            (f"failed: {str(e)}", now(), scan_id),
        )
        conn.commit()
        conn.close()


@app.get("/")
def home():
    return {
        "message": "CVD Backend is running",
        "status": "ok",
    }


@app.post("/api/auth/register")
def register(request: RegisterRequest):
    if len(request.username.strip()) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters.")

    if len(request.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")

    conn = get_conn()

    existing = conn.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        (request.username.strip(), request.email.strip()),
    ).fetchone()

    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists.")

    password_hash = hash_password(request.password)

    cur = conn.execute(
        """
        INSERT INTO users
        (username, email, password_hash, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            request.username.strip(),
            request.email.strip(),
            password_hash,
            now(),
        ),
    )

    conn.commit()
    user_id = cur.lastrowid
    conn.close()

    token = create_token(user_id, request.username.strip())

    return {
        "token": token,
        "user": {
            "id": user_id,
            "username": request.username.strip(),
            "email": request.email.strip(),
        },
    }


@app.post("/api/auth/login")
def login(request: LoginRequest):
    conn = get_conn()

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (request.username.strip(),),
    ).fetchone()

    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    if not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = create_token(user["id"], user["username"])

    return {
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
        },
    }


@app.get("/api/me")
def me(user=Depends(get_current_user)):
    return user


@app.post("/api/scans")
def create_scan(
    request: MultiScanRequest,
    background_tasks: BackgroundTasks,
    user=Depends(get_current_user),
):
    target = request.target.strip()

    if not validate_target(target):
        raise HTTPException(
            status_code=400,
            detail="Invalid target. Use IPv4, CIDR, domain, or http/https URL.",
        )

    clean_engines = {}

    for engine_name, config in request.engines.items():
        if engine_name not in ENGINE_RUNNERS:
            continue

        if config.intensity not in ["light", "normal", "deep", "full"]:
            raise HTTPException(status_code=400, detail=f"Invalid intensity for {engine_name}.")

        if config.brutality not in ["safe", "balanced", "aggressive"]:
            raise HTTPException(status_code=400, detail=f"Invalid brutality for {engine_name}.")

        clean_engines[engine_name] = config

    enabled_count = sum(1 for item in clean_engines.values() if item.enabled)

    if enabled_count == 0:
        raise HTTPException(status_code=400, detail="Select at least one scan engine.")

    estimated_minutes = calculate_estimate(clean_engines)

    engines_json = json.dumps(
        {
            key: value.model_dump()
            for key, value in clean_engines.items()
        }
    )

    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO scan_jobs
        (user_id, target, status, selected_engines, estimated_minutes, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            target,
            "queued",
            engines_json,
            estimated_minutes,
            now(),
        ),
    )

    conn.commit()
    scan_id = cur.lastrowid
    conn.close()

    background_tasks.add_task(
        run_scan_job,
        scan_id,
        target,
        json.loads(engines_json),
    )

    return {
        "scan_id": scan_id,
        "status": "queued",
        "estimated_minutes": estimated_minutes,
    }


@app.get("/api/scans/history")
def scan_history(user=Depends(get_current_user)):
    conn = get_conn()

    rows = conn.execute(
        """
        SELECT *
        FROM scan_jobs
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 50
        """,
        (user["id"],),
    ).fetchall()

    conn.close()

    jobs = []

    for row in rows:
        jobs.append(
            {
                "id": row["id"],
                "target": row["target"],
                "status": row["status"],
                "selected_engines": json.loads(row["selected_engines"]),
                "estimated_minutes": row["estimated_minutes"],
                "created_at": row["created_at"],
                "completed_at": row["completed_at"],
                "counts": severity_counts(row["id"]),
            }
        )

    return {
        "jobs": jobs,
    }


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: int, user=Depends(get_current_user)):
    conn = get_conn()

    scan = conn.execute(
        """
        SELECT *
        FROM scan_jobs
        WHERE id = ? AND user_id = ?
        """,
        (scan_id, user["id"]),
    ).fetchone()

    if not scan:
        conn.close()
        raise HTTPException(status_code=404, detail="Scan not found.")

    output_rows = conn.execute(
        """
        SELECT engine, raw_output, created_at
        FROM scan_outputs
        WHERE scan_id = ?
        ORDER BY id ASC
        """,
        (scan_id,),
    ).fetchall()

    vulnerability_rows = conn.execute(
        """
        SELECT *
        FROM vulnerabilities
        WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            id DESC
        """,
        (scan_id,),
    ).fetchall()

    conn.close()

    raw_outputs = {}

    for row in output_rows:
        raw_outputs[row["engine"]] = row["raw_output"]

    vulnerabilities = []

    for row in vulnerability_rows:
        vulnerabilities.append(
            {
                "id": row["id"],
                "target": row["target"],
                "engine": row["engine"],
                "title": row["title"],
                "severity": row["severity"],
                "cve": row["cve"],
                "cvss": row["cvss"],
                "affected_component": row["affected_component"],
                "description": row["description"],
                "remediation": row["remediation"],
                "created_at": row["created_at"],
            }
        )

    return {
        "scan": {
            "id": scan["id"],
            "target": scan["target"],
            "status": scan["status"],
            "selected_engines": json.loads(scan["selected_engines"]),
            "estimated_minutes": scan["estimated_minutes"],
            "created_at": scan["created_at"],
            "completed_at": scan["completed_at"],
            "counts": severity_counts(scan_id),
        },
        "raw_outputs": raw_outputs,
        "vulnerabilities": vulnerabilities,
    }


@app.get("/api/vulnerabilities")
def all_vulnerabilities(user=Depends(get_current_user)):
    conn = get_conn()

    rows = conn.execute(
        """
        SELECT v.*
        FROM vulnerabilities v
        JOIN scan_jobs s ON s.id = v.scan_id
        WHERE s.user_id = ?
        ORDER BY v.id DESC
        LIMIT 200
        """,
        (user["id"],),
    ).fetchall()

    conn.close()

    vulnerabilities = [dict(row) for row in rows]

    return {
        "vulnerabilities": vulnerabilities,
    }