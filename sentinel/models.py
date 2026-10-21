from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Integer, Float, Boolean, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

def now():
    return datetime.now(timezone.utc)

class SecurityEvent(Base):
    __tablename__ = 'security_events'
    event_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16), default='1.0')
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    source_type: Mapped[str] = mapped_column(String(40), default='synthetic')
    event_category: Mapped[str] = mapped_column(String(40), index=True)
    event_action: Mapped[str] = mapped_column(String(80))
    outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default='low', index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    process_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parent_process_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    command_line: Mapped[str | None] = mapped_column(String(512), nullable=True)
    authentication_method: Mapped[str | None] = mapped_column(String(40), nullable=True)
    event_source: Mapped[str] = mapped_column(String(80), default='sentinel-generator')
    raw_event: Mapped[str] = mapped_column(Text, default='{}')
    normalized_attributes: Mapped[str] = mapped_column(Text, default='{}')
    scenario_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    replay_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    __table_args__ = (Index('ix_events_time_severity', 'timestamp', 'severity'),)

class DetectionRule(Base):
    __tablename__ = 'detection_rules'
    rule_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    version: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    technique_name: Mapped[str | None] = mapped_column(String(120), nullable=True)

class DetectionFinding(Base):
    __tablename__ = 'detection_findings'
    finding_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey('detection_rules.rule_id'))
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    explanation: Mapped[str] = mapped_column(Text)
    evidence_ids: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text)
    dedupe_key: Mapped[str] = mapped_column(String(240), unique=True)
    technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    technique_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    replay_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

class Incident(Base):
    __tablename__ = 'incidents'
    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(24), default='open', index=True)
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)
    correlation_key: Mapped[str] = mapped_column(String(240), unique=True)
    summary: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class IncidentEvent(Base):
    __tablename__ = 'incident_events'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey('incidents.incident_id', ondelete='CASCADE'))
    event_id: Mapped[str] = mapped_column(ForeignKey('security_events.event_id', ondelete='CASCADE'))
    __table_args__ = (UniqueConstraint('incident_id', 'event_id'),)

class Entity(Base):
    __tablename__ = 'entities'
    entity_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(32), index=True)
    label: Mapped[str] = mapped_column(String(160))

class EntityRelationship(Base):
    __tablename__ = 'entity_relationships'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[str] = mapped_column(ForeignKey('entities.entity_id', ondelete='CASCADE'))
    target_id: Mapped[str] = mapped_column(ForeignKey('entities.entity_id', ondelete='CASCADE'))
    relationship_type: Mapped[str] = mapped_column(String(40))
    evidence: Mapped[str] = mapped_column(Text)
    inferred: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (UniqueConstraint('source_id', 'target_id', 'relationship_type'),)

class Investigation(Base):
    __tablename__ = 'investigations'
    investigation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey('incidents.incident_id'))
    provider: Mapped[str] = mapped_column(String(32), default='deterministic')
    prompt_version: Mapped[str] = mapped_column(String(32), default='fallback-v1')
    evidence_package_id: Mapped[str] = mapped_column(String(36))
    output: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class ResponseAction(Base):
    __tablename__ = 'response_actions'
    action_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey('incidents.incident_id'))
    action_type: Mapped[str] = mapped_column(String(48))
    target: Mapped[str] = mapped_column(String(180))
    rationale: Mapped[str] = mapped_column(Text)
    expected_impact: Mapped[str] = mapped_column(Text)
    risk: Mapped[str] = mapped_column(String(24))
    payload_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(24), default='pending', index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class ApprovalRecord(Base):
    __tablename__ = 'approval_records'
    approval_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    action_id: Mapped[str] = mapped_column(ForeignKey('response_actions.action_id'))
    payload_hash: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(16))
    analyst: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class ReplayScenario(Base):
    __tablename__ = 'replay_scenarios'
    scenario_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    event_count: Mapped[int] = mapped_column(Integer)
    expected_rules: Mapped[str] = mapped_column(Text)
    seed: Mapped[int] = mapped_column(Integer)

class ReplaySession(Base):
    __tablename__ = 'replay_sessions'
    replay_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(ForeignKey('replay_scenarios.scenario_id'))
    state: Mapped[str] = mapped_column(String(20), index=True)
    speed: Mapped[float] = mapped_column(Float)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    audit_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(80))
    object_type: Mapped[str] = mapped_column(String(48))
    object_id: Mapped[str] = mapped_column(String(80))
    details: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class ModelMetadata(Base):
    __tablename__ = 'model_metadata'
    model_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    algorithm: Mapped[str] = mapped_column(String(80))
    version: Mapped[str] = mapped_column(String(32))
    feature_schema: Mapped[str] = mapped_column(Text)
    threshold: Mapped[float] = mapped_column(Float)
    trained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(24))
