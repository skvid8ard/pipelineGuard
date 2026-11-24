import json
import os
import re
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import Depends, FastAPI, Header, HTTPException, File, UploadFile
from pydantic import BaseModel, Field

DB_PATH = Path(os.getenv("DB_PATH", "scans.db"))
TENANTS = {
    "token-a": {"id": "A", "plan": "Free", "limit": 2},
    "token-b": {"id": "B", "plan": "Pro", "limit": 5},
}

app = FastAPI(title="PipelineGuard MVP")


class ScanRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=65536)


def current_tenant(authorization: str | None = Header(default=None)):
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() == "bearer":
        for expected, tenant in TENANTS.items():
            if secrets.compare_digest(token, expected):
                return tenant
    raise HTTPException(401, "Invalid API token", headers={"WWW-Authenticate": "Bearer"})


def connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def analyze(document):
    findings = []

    def visit(value):
        if isinstance(value, dict):
            image = value.get("image")
            if isinstance(image, dict):
                image = image.get("name")
            if isinstance(image, str) and image.endswith(":latest"):
                findings.append("MUTABLE_IMAGE_TAG")
            for key, child in value.items():
                if key == "script":
                    commands = child if isinstance(child, list) else [child]
                    for command in commands:
                        if isinstance(command, str) and re.search(r"\bcurl\b[^\n|]*\|\s*(?:ba)?sh\b", command):
                            findings.append("PIPED_SHELL")
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, str) and "docker:dind" in value:
            findings.append("DIND_USAGE")

    visit(document)
    return findings


def serialize(row):
    result = dict(row)
    result["findings"] = json.loads(result["findings"])
    return result

@app.get("/me")
def me(tenant=Depends(current_tenant)):
    with closing(connect()) as db:
        used = db.execute("SELECT COUNT(*) FROM scans WHERE tenant_id = ?", (tenant["id"],)).fetchone()[0]
    return {"tenant": tenant["id"], "plan": tenant["plan"], "limit": tenant["limit"], "used": used}

@app.post("/scans", status_code=201)
async def create_scan(file: UploadFile = File(...), tenant=Depends(current_tenant)):
    content = await file.read()

    if len(content) > 64 * 1024:
        raise HTTPException(413, "File too large (max 64 KB)")

    try:
        document = yaml.safe_load(content.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError):
        raise HTTPException(400, "Invalid YAML")

    if not isinstance(document, dict):
        raise HTTPException(400, "Expected a YAML mapping")

    findings = analyze(document)
    created_at = datetime.now(timezone.utc).isoformat()

    with closing(connect()) as db, db:
        db.execute("BEGIN IMMEDIATE")
        used = db.execute(
            "SELECT COUNT(*) FROM scans WHERE tenant_id = ?",
            (tenant["id"],)
        ).fetchone()[0]

        if used >= tenant["limit"]:
            raise HTTPException(409, "PLAN_LIMIT_REACHED")

        cursor = db.execute(
            "INSERT INTO scans (tenant_id, filename, findings, created_at) VALUES (?, ?, ?, ?)",
            (tenant["id"], file.filename, json.dumps(findings), created_at),
        )
        scan_id = cursor.lastrowid

    return {
        "id": scan_id,
        "tenant": tenant["id"],
        "filename": file.filename,
        "findings": findings,
        "created_at": created_at
    }

@app.get("/scans")
def list_scans(tenant=Depends(current_tenant)):
    with closing(connect()) as db:
        rows = db.execute(
            "SELECT * FROM scans WHERE tenant_id = ? ORDER BY id", (tenant["id"],)
        ).fetchall()
    return [serialize(row) for row in rows]


@app.get("/scans/{scan_id}")
def get_scan(scan_id: int, tenant=Depends(current_tenant)):
    with closing(connect()) as db:
        row = db.execute(
            "SELECT * FROM scans WHERE id = ? AND tenant_id = ?",
            (scan_id, tenant["id"]),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "Scan not found")
    return serialize(row)

DB_PATH.parent.mkdir(parents=True, exist_ok=True)
with closing(connect()) as db, db:
    db.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        findings TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")