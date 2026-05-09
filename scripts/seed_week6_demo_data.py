import sys
from pathlib import Path
from datetime import datetime, timedelta

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.database import Base, engine, SessionLocal
from app.models import VulnerabilityReport
from app.core_logic import calculate_completeness_score

# Safely set optional fields only if they exist in the model
def set_optional_field(report, field_name, value):
    # Check if the report object has this attribute (column)
    if hasattr(report, field_name):
        setattr(report, field_name, value)

def build_report(
    title,
    product,
    hardware_version,
    firmware_version,
    tested_country,
    cvss_score,
    description,
    impact,
    reproduction_steps,
    recommended_mitigation,
    reporter_contact,
    status,
    created_at,
    first_status_changed_at=None,
    closed_at=None,
    attachment_filename=None,
    attachment_size_bytes=None,
):
    data_for_score = {
        "title": title,
        "product": product,
        "hardware_version": hardware_version,
        "firmware_version": firmware_version,
        "description": description,
        "impact": impact,
        "reproduction_steps": reproduction_steps,
        "reporter_contact": reporter_contact,
    }

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
        status=status,
        created_at=created_at,
        completeness_score=calculate_completeness_score(data_for_score),
    )

    set_optional_field(report, "updated_at", first_status_changed_at or created_at)
    set_optional_field(report, "first_status_changed_at", first_status_changed_at)
    set_optional_field(report, "closed_at", closed_at)
    set_optional_field(report, "attachment_filename", attachment_filename)
    set_optional_field(report, "attachment_size_bytes", attachment_size_bytes)

    return report


def seed_demo_data():
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        # This clears only the demo vulnerability report table.
        # It does not delete code, templates, tests, or your Git history.
        db.query(VulnerabilityReport).delete()
        db.commit()

        now = datetime.utcnow()

        reports = [
            build_report(
                title="Hard-coded cryptographic key exposure",
                product="DemoRouter AX3000",
                hardware_version="V1.0",
                firmware_version="1.0.4 Build 20260415",
                tested_country="United States",
                cvss_score=7.5,
                description=(
                    "During testing of the firmware image, a hard-coded cryptographic key "
                    "was identified in a configuration file. The key appears to be reused "
                    "across multiple simulated devices instead of being generated uniquely."
                ),
                impact=(
                    "An attacker with access to the firmware image could extract the key "
                    "and potentially decrypt protected configuration data in a simulated environment."
                ),
                reproduction_steps=(
                    "1. Download the synthetic firmware image.\n"
                    "2. Extract the firmware archive using a local analysis tool.\n"
                    "3. Search the extracted files for static key strings.\n"
                    "4. Confirm that the same key value appears in multiple configuration files."
                ),
                recommended_mitigation=(
                    "Remove hard-coded keys from firmware files. Generate unique keys per device "
                    "or per installation and store them using a secure key management process."
                ),
                reporter_contact="security.researcher@example.com",
                status="New",
                created_at=now - timedelta(days=1),
                attachment_filename="firmware_key_evidence.txt",
                attachment_size_bytes=18420,
            ),
            build_report(
                title="Cross-site scripting in admin interface",
                product="DemoGateway Web Console",
                hardware_version="V2.1",
                firmware_version="2.3.8 Build 20260410",
                tested_country="United States",
                cvss_score=6.1,
                description=(
                    "The device name field in the simulated admin interface does not properly "
                    "sanitize user input before rendering it back in the dashboard."
                ),
                impact=(
                    "An attacker with access to the admin interface could inject script-like input. "
                    "If another administrator views the dashboard, the content could execute in the browser."
                ),
                reproduction_steps=(
                    "1. Log in to the simulated admin interface.\n"
                    "2. Navigate to device settings.\n"
                    "3. Enter a script-like test string into the device name field.\n"
                    "4. Save the setting.\n"
                    "5. Return to the dashboard and observe that output encoding is missing."
                ),
                recommended_mitigation=(
                    "Apply server-side input validation and context-aware output encoding for all "
                    "user-controlled fields rendered in HTML templates."
                ),
                reporter_contact="vdp.tester@example.com",
                status="Needs Info",
                created_at=now - timedelta(days=2),
                first_status_changed_at=now - timedelta(days=1, hours=12),
                attachment_filename="xss_reproduction_steps.png",
                attachment_size_bytes=246800,
            ),
            build_report(
                title="Insecure firmware update validation",
                product="DemoSmartHub 500",
                hardware_version="V1.2",
                firmware_version="3.0.1 Build 20260401",
                tested_country="Canada",
                cvss_score=8.1,
                description=(
                    "The simulated firmware update process checks the firmware version number "
                    "but does not fully verify the integrity or authenticity of the uploaded firmware package."
                ),
                impact=(
                    "If this weakness existed in a real product, an attacker could attempt to upload "
                    "an unauthorized firmware package, leading to installation of untrusted code."
                ),
                reproduction_steps=(
                    "1. Access the simulated firmware update page.\n"
                    "2. Upload a modified test firmware package with a valid-looking version number.\n"
                    "3. Observe that only limited validation is performed.\n"
                    "4. Confirm that signature or hash validation is not enforced."
                ),
                recommended_mitigation=(
                    "Enforce cryptographic signature verification before accepting firmware updates. "
                    "Reject unsigned, modified, or unverifiable firmware packages."
                ),
                reporter_contact="firmware.researcher@example.com",
                status="Triaged",
                created_at=now - timedelta(days=3),
                first_status_changed_at=now - timedelta(days=2),
                attachment_filename="firmware_validation_notes.pdf",
                attachment_size_bytes=512000,
            ),
            build_report(
                title="Weak password reset token expiration",
                product="DemoCloud Account Portal",
                hardware_version="N/A",
                firmware_version="Web Application Version 1.5.2",
                tested_country="United States",
                cvss_score=5.4,
                description=(
                    "The password reset token in the simulated account portal remains valid for "
                    "an extended period after generation and can still be used after a password reset."
                ),
                impact=(
                    "If a reset token is exposed, an attacker may have more time to reuse it. "
                    "In a real environment, this could increase account takeover risk."
                ),
                reproduction_steps=(
                    "1. Request a password reset link from the simulated account portal.\n"
                    "2. Use the reset link to change the account password.\n"
                    "3. Attempt to reuse the same reset link after the password change.\n"
                    "4. Observe that the token is still accepted in the simulated workflow."
                ),
                recommended_mitigation=(
                    "Set a short expiration period for password reset tokens and invalidate each token "
                    "immediately after successful use."
                ),
                reporter_contact="appsec.reporter@example.com",
                status="Closed",
                created_at=now - timedelta(days=5),
                first_status_changed_at=now - timedelta(days=4),
                closed_at=now - timedelta(days=2),
                attachment_filename="password_reset_test_log.txt",
                attachment_size_bytes=32768,
            ),
        ]

        db.add_all(reports)
        db.commit()

        print("Week 6 synthetic demo data created successfully.")
        print(f"Inserted {len(reports)} reports.")
        print("Open http://127.0.0.1:8000/dashboard")
        print("Open http://127.0.0.1:8000/metrics")

    finally:
        db.close()


if __name__ == "__main__":
    seed_demo_data()