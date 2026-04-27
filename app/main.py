from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .database import Base, engine, SessionLocal
from .models import VulnerabilityReport

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
    title: str = Form(...),
    product: str = Form(...),
    hardware_version: str = Form(""),
    firmware_version: str = Form(...),
    tested_country: str = Form(""),
    cvss_score: float | None = Form(None),
    description: str = Form(...),
    impact: str = Form(""),
    reproduction_steps: str = Form(""),
    recommended_mitigation: str = Form(""),
    reporter_contact: str = Form(""),
    db: Session = Depends(get_db)
):
    report = VulnerabilityReport(
        title=title,
        product=product,
        hardware_version=hardware_version,
        firmware_version=firmware_version,
        tested_country=tested_country,
        cvss_score=cvss_score,
        description=description,
        impact=impact,
        reproduction_steps=reproduction_steps,
        recommended_mitigation=recommended_mitigation,
        reporter_contact=reporter_contact,
        status="New"
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

@app.post("/dashboard/{report_id}/status")
def update_report_status(
    report_id: int,
    status: str = Form(...),
    db: Session = Depends(get_db)
):
    report = db.query(VulnerabilityReport).filter(VulnerabilityReport.id == report_id).first()

    if report:
        report.status = status
        db.commit()

    return RedirectResponse(url="/dashboard", status_code=303)