import json
import os
import re
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import Depends, FastAPI, Header, HTTPException
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