from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_submission_page_loads():
    response = client.get("/")
    assert response.status_code == 200


def test_dashboard_loads():
    response = client.get("/dashboard")
    assert response.status_code == 200


def test_metrics_page_loads():
    response = client.get("/metrics")
    assert response.status_code == 200


def test_incomplete_submission_is_rejected():
    response = client.post(
        "/submit",
        data={
            "title": "",
            "product": "",
            "hardware_version": "",
            "firmware_version": "",
            "description": "",
            "impact": "",
            "reproduction_steps": "",
            "recommended_mitigation": "",
            "reporter_contact": "",
        },
    )
    assert response.status_code in (400, 422)