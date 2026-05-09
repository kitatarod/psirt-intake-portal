from collections import Counter
from fastapi import FastAPI, Form, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import Base, engine, SessionLocal
from app.models import VulnerabilityReport
from app.core_logic import validate_submission, transition_status, calculate_response_metrics
app = FastAPI(title="PSIRT Intake Portal")

Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory="templates")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={}
    )


@app.get("/submit", response_class=HTMLResponse)
def show_submit_form(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="submit.html",
        context={}
    )


@app.post("/submit")
def submit_report(
    title: str = Form(""),
    product: str = Form(""),
    hardware_version: str = Form(""),
    firmware_version: str = Form(""),
    tested_country: str = Form(""),
    cvss_score: float | None = Form(None),
    description: str = Form(""),
    impact: str = Form(""),
    reproduction_steps: str = Form(""),
    recommended_mitigation: str = Form(""),
    reporter_contact: str = Form(""),
    db: Session = Depends(get_db)
):
    submission_data = {
        "title": title,
        "product": product,
        "hardware_version": hardware_version,
        "firmware_version": firmware_version,
        "description": description,
        "impact": impact,
        "reproduction_steps": reproduction_steps,
        "reporter_contact": reporter_contact,
    }

    validation = validate_submission(submission_data)

    if not validation.is_valid:
        raise HTTPException(
            status_code=400,
            detail=validation.errors
        )

    report = VulnerabilityReport(
        title=validation.cleaned_data["title"],
        product=validation.cleaned_data["product"],
        hardware_version=validation.cleaned_data["hardware_version"],
        firmware_version=validation.cleaned_data["firmware_version"],
        tested_country=tested_country,
        cvss_score=cvss_score,
        description=validation.cleaned_data["description"],
        impact=validation.cleaned_data["impact"],
        reproduction_steps=validation.cleaned_data["reproduction_steps"],
        recommended_mitigation=recommended_mitigation,
        reporter_contact=validation.cleaned_data["reporter_contact"],
        status="New",
        completeness_score=validation.completeness_score
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    return RedirectResponse(url="/submit/success", status_code=303)


@app.get("/submit/success", response_class=HTMLResponse)
def submit_success(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="success.html",
        context={}
    )

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    reports = db.query(VulnerabilityReport).all()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"reports": reports}
    )

@app.get("/metrics", response_class=HTMLResponse)
def metrics(request: Request, db: Session = Depends(get_db)):
    reports = db.query(VulnerabilityReport).all()

    total_reports = len(reports)

    if total_reports > 0:
        average_completeness = round(
            sum(report.completeness_score or 0 for report in reports) / total_reports,
            2
        )
    else:
        average_completeness = 0

    status_counts = Counter(report.status for report in reports)

    response_metric_rows = []
    first_response_values = []
    closure_values = []

    for report in reports:
        metric = calculate_response_metrics(
            created_at=report.created_at,
            first_status_changed_at=report.first_status_changed_at,
            closed_at=report.closed_at
        )

        days_to_first_status_change = metric["days_to_first_status_change"]
        days_to_closure = metric["days_to_closure"]

        if days_to_first_status_change is not None:
            first_response_values.append(days_to_first_status_change)

        if days_to_closure is not None:
            closure_values.append(days_to_closure)

        response_metric_rows.append({
            "id": report.id,
            "title": report.title,
            "status": report.status,
            "completeness_score": report.completeness_score,
            "days_to_first_status_change": days_to_first_status_change,
            "days_to_closure": days_to_closure,
        })

    average_days_to_first_status_change = (
        round(sum(first_response_values) / len(first_response_values), 2)
        if first_response_values
        else "Not available yet"
    )

    average_days_to_closure = (
        round(sum(closure_values) / len(closure_values), 2)
        if closure_values
        else "Not available yet"
    )

    return templates.TemplateResponse(
        request=request,
        name="metrics.html",
        context={
            "total_reports": total_reports,
            "average_completeness": average_completeness,
            "status_counts": dict(status_counts),
            "average_days_to_first_status_change": average_days_to_first_status_change,
            "average_days_to_closure": average_days_to_closure,
            "response_metric_rows": response_metric_rows,
        }
    )
@app.post("/dashboard/{report_id}/status")
def update_report_status(
    report_id: int,
    status: str = Form(...),
    db: Session = Depends(get_db)
):
    report = db.query(VulnerabilityReport).filter(VulnerabilityReport.id == report_id).first()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    transition = transition_status(report.status, status)

    if not transition.is_valid:
        raise HTTPException(status_code=400, detail=transition.message)

    # Record the first time an analyst changes the report status.
    if report.first_status_changed_at is None and status != report.status:
        report.first_status_changed_at = transition.changed_at

    # Record the closure timestamp when the report moves to Closed.
    if status == "Closed":
        report.closed_at = transition.changed_at

    # Keep a general last-updated timestamp for metrics and audit visibility.
    report.updated_at = transition.changed_at
    report.status = status

    db.commit()

    return RedirectResponse(url="/dashboard", status_code=303)