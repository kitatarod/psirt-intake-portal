from datetime import datetime, timedelta

from app.core_logic import (
    calculate_completeness_score,
    calculate_response_metrics,
    transition_status,
    validate_attachment,
    validate_submission,
)


VALID_REPORT = {
    "title": "Diagnostic endpoint information disclosure",
    "product": "Demo Router X100",
    "hardware_version": "HW v2.0",
    "firmware_version": "FW 1.0.3",
    "description": "The diagnostic endpoint exposes synthetic device configuration data.",
    "impact": "An attacker may view limited diagnostic details in this demo scenario.",
    "reproduction_steps": "Open the diagnostic endpoint, send the crafted request, and review the response body.",
    "reporter_contact": "researcher@example.com",
}


def test_validate_submission_accepts_complete_report():
    result = validate_submission(VALID_REPORT)

    assert result.is_valid is True
    assert result.errors == []
    assert result.cleaned_data["hardware_version"] == "HW v2.0"
    assert result.cleaned_data["firmware_version"] == "FW 1.0.3"
    assert result.completeness_score == 100


def test_validate_submission_requires_hardware_and_firmware_separately():
    report = VALID_REPORT.copy()
    report["hardware_version"] = ""
    report["firmware_version"] = ""

    result = validate_submission(report)

    assert result.is_valid is False
    assert "Hardware version is required." in result.errors
    assert "Firmware version is required." in result.errors


def test_validate_submission_rejects_invalid_email():
    report = VALID_REPORT.copy()
    report["reporter_contact"] = "not-an-email"

    result = validate_submission(report)

    assert result.is_valid is False
    assert "Reporter contact must be a valid email address." in result.errors


def test_calculate_completeness_score_reflects_missing_fields():
    report = VALID_REPORT.copy()
    report["hardware_version"] = ""
    report["firmware_version"] = ""

    score = calculate_completeness_score(report)

    assert score == 75


def test_validate_attachment_accepts_allowed_file_type_and_size():
    result = validate_attachment("evidence.pcap", 1024)

    assert result.is_valid is True
    assert result.safe_filename is not None
    assert result.safe_filename.endswith(".pcap")


def test_validate_attachment_rejects_disallowed_file_type():
    result = validate_attachment("malware.exe", 1024)

    assert result.is_valid is False
    assert "not allowed" in result.errors[0]


def test_validate_attachment_rejects_oversized_file():
    result = validate_attachment("large-log.txt", 6 * 1024 * 1024)

    assert result.is_valid is False
    assert "5 MB" in result.errors[0]


def test_transition_status_allows_new_to_triaged():
    result = transition_status("New", "Triaged")

    assert result.is_valid is True
    assert result.to_status == "Triaged"
    assert result.changed_at is not None


def test_transition_status_blocks_reopen_from_closed():
    result = transition_status("Closed", "New")

    assert result.is_valid is False
    assert "Cannot move status" in result.message


def test_response_metrics_are_calculated_in_days():
    created_at = datetime(2026, 4, 1, 9, 0, 0)
    first_change = created_at + timedelta(days=1, hours=12)
    closed_at = created_at + timedelta(days=5)

    metrics = calculate_response_metrics(created_at, first_change, closed_at)

    assert metrics["days_to_first_status_change"] == 1.5
    assert metrics["days_to_closure"] == 5.0


def test_response_metrics_return_none_when_dates_missing():
    created_at = datetime(2026, 4, 1, 9, 0, 0)

    metrics = calculate_response_metrics(created_at)

    assert metrics["days_to_first_status_change"] is None
    assert metrics["days_to_closure"] is None
