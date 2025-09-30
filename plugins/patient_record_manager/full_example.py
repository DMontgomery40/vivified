"""
Optional full example incorporating SQLAlchemy and cryptography.

This file is not executed by default and is provided as reference material to
extend the minimal plugin. To try it locally:

  1) pip install sqlalchemy cryptography
  2) export PRM_FULL=1
  3) python full_example.py

Notes:
  - This mirrors the Phase 7 runbook patterns but omits external service calls.
  - Keep PHI encrypted at rest and avoid PHI in logs.
"""
from __future__ import annotations

import os
from typing import Any, Dict


def _bootstrap_full() -> None:
    # Lazy import heavy dependencies to avoid impacting CI
    from datetime import datetime  # noqa: WPS433
    from sqlalchemy import Column, String, DateTime, Text, Boolean, create_engine  # type: ignore  # noqa: WPS433,E501
    from sqlalchemy.orm import declarative_base, sessionmaker  # type: ignore  # noqa: WPS433
    from cryptography.fernet import Fernet  # type: ignore  # noqa: WPS433

    Base = declarative_base()

    class PatientRecord(Base):  # type: ignore[misc]
        __tablename__ = "patient_records"
        id = Column(String, primary_key=True)
        patient_id_hash = Column(String, index=True)
        record_type = Column(String)
        encrypted_data = Column(Text)
        encryption_metadata = Column(Text)
        created_at = Column(DateTime, default=datetime.utcnow)
        created_by = Column(String)
        accessed_at = Column(DateTime)
        accessed_by = Column(String)
        is_active = Column(Boolean, default=True)

    engine = create_engine(os.getenv("DATABASE_URL", "sqlite:///./prm.sqlite3"))
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    key = os.getenv("ENCRYPTION_KEY") or Fernet.generate_key().decode()
    f = Fernet(key.encode())

    # Write a sample record (demo only)
    enc = f.encrypt(b"{\"type\":\"clinical\",\"content\":\"example\"}")
    rec = PatientRecord(
        id="rec-1",
        patient_id_hash="example",
        record_type="clinical",
        encrypted_data=enc.decode(),
        encryption_metadata="{}",
        created_by="demo",
    )
    session.add(rec)
    session.commit()
    print("Wrote example record to database (encrypted)")


if __name__ == "__main__":  # pragma: no cover
    if os.getenv("PRM_FULL"):
        _bootstrap_full()
    else:
        print("Set PRM_FULL=1 to run the full example scaffolding.")

