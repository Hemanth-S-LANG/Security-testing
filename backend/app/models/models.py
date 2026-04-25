import uuid
from datetime import datetime
from sqlalchemy import String, Text, Integer, Float, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.db.database import Base


def gen_uuid():
    return str(uuid.uuid4())


class TestRun(Base):
    __tablename__ = "test_runs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    total_cases: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    test_cases: Mapped[list["TestCase"]] = relationship("TestCase", back_populates="run", cascade="all, delete-orphan")


class TestCase(Base):
    __tablename__ = "test_cases"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    run_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("test_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    endpoint_path: Mapped[str] = mapped_column(String(500), nullable=False)
    http_method: Mapped[str] = mapped_column(String(10), nullable=False)
    owasp_category: Mapped[str] = mapped_column(String(100), nullable=False)
    attack_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload_used: Mapped[str] = mapped_column(Text, nullable=True)
    target_parameter: Mapped[str] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    run: Mapped["TestRun"] = relationship("TestRun", back_populates="test_cases")
    result: Mapped["TestResult"] = relationship("TestResult", back_populates="test_case", uselist=False, cascade="all, delete-orphan")


class TestResult(Base):
    __tablename__ = "test_results"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("test_cases.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    result_status: Mapped[str] = mapped_column(String(20), nullable=False)
    http_status_code: Mapped[int] = mapped_column(Integer, nullable=True)
    response_body: Mapped[str] = mapped_column(Text, nullable=True)
    response_headers: Mapped[dict] = mapped_column(JSONB, nullable=True)
    response_time_ms: Mapped[float] = mapped_column(Float, nullable=True)
    vulnerability_detail: Mapped[str] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    test_case: Mapped["TestCase"] = relationship("TestCase", back_populates="result")