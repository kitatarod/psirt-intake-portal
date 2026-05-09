from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Float
from .database import Base


class VulnerabilityReport(Base):
    __tablename__ = "vulnerability_reports"

    id = Column(Integer, primary_key=True, index=True)

    title = Column(String(200), nullable=False)
    product = Column(String(100), nullable=False)
    hardware_version = Column(String(100), nullable=True)
    firmware_version = Column(String(100), nullable=False)
    tested_country = Column(String(100), nullable=True)
    cvss_score = Column(Float, nullable=True)

    description = Column(Text, nullable=False)
    impact = Column(Text, nullable=True)
    reproduction_steps = Column(Text, nullable=True)
    recommended_mitigation = Column(Text, nullable=True)
    reporter_contact = Column(String(200), nullable=True)

    status = Column(String(50), default="New")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True)
    first_status_changed_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    completeness_score = Column(Integer, default=0)
    attachment_filename = Column(String(255), nullable=True)
    attachment_size_bytes = Column(Integer, nullable=True)