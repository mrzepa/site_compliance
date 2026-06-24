from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Vet Compliance")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    report_path = Path(os.getenv("VET_COMPLIANCE_REPORT", "reports/compliance_report.json"))
    report = {
        "findings": [],
        "total_devices": 0,
        "compliant_devices": 0,
        "noncompliant_devices": 0,
        "compliance_percent": 100,
        "total_sites": 0,
        "compliant_sites": 0,
        "noncompliant_sites": 0,
        "site_compliance_percent": 100,
    }
    if report_path.exists():
        loaded_report = json.loads(report_path.read_text(encoding="utf-8"))
        report = {**report, **loaded_report}
        if "total_sites" not in loaded_report:
            sites_with_findings = {(finding.get("platform"), finding.get("site")) for finding in report.get("findings", [])}
            report["total_sites"] = len(sites_with_findings)
            report["noncompliant_sites"] = len(sites_with_findings)
            report["compliant_sites"] = 0
            report["site_compliance_percent"] = 0 if sites_with_findings else 100
    return templates.TemplateResponse(request, "index.html", {"report": report, "report_path": report_path})
