"""Week 5 core logic for the PSIRT Intake Portal.

This module keeps the business rules separate from the web routes so the
validation, workflow, attachment handling, and metrics logic can be tested
independently with PyTest.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4
import re


MAX_ATTACHMENT_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
ALLOWED_ATTACHMENT_EXTENSIONS = {
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".txt",
    ".csv",
    ".xlsx",
    ".pcap",
}

REQUIRED_FIELDS = {
    "title": "Vulnerability title",
    "product": "Affected product",
    "hardware_version": "Hardware version",
    "firmware_version": "Firmware version",
    "description": "Vulnerability description",
    "impact": "Impact",
    "reproduction_steps": "Reproduction steps",
    "reporter_contact": "Reporter contact",
}

MIN_LENGTH_RULES = {
    "description": 20,
    "impact": 10,
    "reproduction_steps": 20,
}

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

VALID_STATUSES = ("New", "Needs Info", "Triaged", "Closed")
ALLOWED_TRANSITIONS = {
    "New": {"Needs Info", "Triaged", "Closed"},
    "Needs Info": {"New", "Triaged", "Closed"},
    "Triaged": {"Needs Info", "Closed"},
    "Closed": set(),
}


@dataclass(frozen=True)
class ValidationResult:
    is_valid: bool
    errors: list[str]
    cleaned_data: dict[str, str]
    completeness_score: int


@dataclass(frozen=True)
class AttachmentValidationResult:
    is_valid: bool
    errors: list[str]
    safe_filename: str | None = None


@dataclass(frozen=True)
class StatusTransitionResult:
    is_valid: bool
    from_status: str
    to_status: str
    message: str
    changed_at: datetime | None = None


def clean_text(value: Any) -> str:
    """Convert form/API values to safe trimmed strings for validation."""
    if value is None:
        return ""
    return str(value).strip()


def calculate_completeness_score(data: dict[str, Any]) -> int:
    """Calculate how many required intake fields are populated.

    The score is intentionally simple for the MVP so it can be explained in the
    Week 5 report and demonstrated with synthetic submissions.
    """
    total = len(REQUIRED_FIELDS)
    completed = sum(1 for field in REQUIRED_FIELDS if clean_text(data.get(field)))
    return round((completed / total) * 100)


def validate_submission(data: dict[str, Any]) -> ValidationResult:
    """Validate the vulnerability submission fields used by the current form.

    """
    errors: list[str] = []
    cleaned_data = {field: clean_text(data.get(field)) for field in REQUIRED_FIELDS}

    for field, label in REQUIRED_FIELDS.items():
        if not cleaned_data[field]:
            errors.append(f"{label} is required.")

    for field, minimum_length in MIN_LENGTH_RULES.items():
        value = cleaned_data.get(field, "")
        if value and len(value) < minimum_length:
            errors.append(
                f"{REQUIRED_FIELDS[field]} must be at least {minimum_length} characters."
            )

    reporter_contact = cleaned_data.get("reporter_contact", "")
    if reporter_contact and not EMAIL_PATTERN.match(reporter_contact):
        errors.append("Reporter contact must be a valid email address.")

    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        cleaned_data=cleaned_data,
        completeness_score=calculate_completeness_score(cleaned_data),
    )


def safe_upload_name(original_filename: str) -> str:
    """Generate a randomized filename while preserving the extension."""
    suffix = Path(original_filename).suffix.lower()
    return f"{uuid4().hex}{suffix}"


def validate_attachment(filename: str | None, size_bytes: int) -> AttachmentValidationResult:
    """Validate attachment type and size before storage."""
    errors: list[str] = []
    filename = clean_text(filename)

    if not filename:
        return AttachmentValidationResult(
            is_valid=True,
            errors=[],
            safe_filename=None,
        )

    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_ATTACHMENT_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_ATTACHMENT_EXTENSIONS))
        errors.append(f"Attachment type {suffix or '[no extension]'} is not allowed. Allowed types: {allowed}.")

    if size_bytes < 0:
        errors.append("Attachment size cannot be negative.")
    elif size_bytes > MAX_ATTACHMENT_SIZE_BYTES:
        errors.append("Attachment exceeds the 5 MB maximum file size.")

    return AttachmentValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        safe_filename=safe_upload_name(filename) if len(errors) == 0 else None,
    )


def can_transition(current_status: str, new_status: str) -> bool:
    """Return True when the requested workflow status movement is allowed."""
    return new_status in ALLOWED_TRANSITIONS.get(current_status, set())


def transition_status(current_status: str, new_status: str) -> StatusTransitionResult:
    """Validate and return a status transition result for the dashboard."""
    current_status = clean_text(current_status)
    new_status = clean_text(new_status)

    if current_status not in VALID_STATUSES:
        return StatusTransitionResult(False, current_status, new_status, "Current status is invalid.")

    if new_status not in VALID_STATUSES:
        return StatusTransitionResult(False, current_status, new_status, "Requested status is invalid.")

    if current_status == new_status:
        return StatusTransitionResult(True, current_status, new_status, "Status unchanged.", datetime.now(timezone.utc))

    if not can_transition(current_status, new_status):
        return StatusTransitionResult(
            False,
            current_status,
            new_status,
            f"Cannot move status from {current_status} to {new_status}.",
        )

    return StatusTransitionResult(
        True,
        current_status,
        new_status,
        f"Status changed from {current_status} to {new_status}.",
        datetime.now(timezone.utc),
    )


def days_between(start: datetime | None, end: datetime | None) -> float | None:
    """Return elapsed time in days rounded to two decimals."""
    if start is None or end is None:
        return None
    return round((end - start).total_seconds() / 86400, 2)


def calculate_response_metrics(
    created_at: datetime,
    first_status_changed_at: datetime | None = None,
    closed_at: datetime | None = None,
) -> dict[str, float | None]:
    """Calculate PSIRT responsiveness metrics in days.

    """
    return {
        "days_to_first_status_change": days_between(created_at, first_status_changed_at),
        "days_to_closure": days_between(created_at, closed_at),
    }
