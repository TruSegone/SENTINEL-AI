from datetime import datetime, timezone
from ipaddress import ip_address
import json
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

class EventIn(BaseModel):
    """Validated event contract; extras and naive timestamps are rejected at ingress."""
    model_config = ConfigDict(extra='forbid')
    event_id: str = Field(min_length=1, max_length=80)
    schema_version: str = Field(default='1.0', max_length=16)
    timestamp: datetime
    observed_at: datetime | None = None
    source_type: str = Field(default='synthetic', max_length=40)
    event_category: str = Field(max_length=40)
    event_action: str = Field(max_length=80)
    outcome: str | None = Field(default=None, max_length=24)
    severity: Literal['info', 'low', 'medium', 'high', 'critical'] = 'low'
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=128)
    hostname: str | None = Field(default=None, max_length=128)
    process_name: str | None = Field(default=None, max_length=128)
    parent_process_name: str | None = Field(default=None, max_length=128)
    command_line: str | None = Field(default=None, max_length=512)
    authentication_method: str | None = Field(default=None, max_length=40)
    event_source: str = Field(default='sentinel-generator', max_length=80)
    raw_event: dict[str, Any] = Field(default_factory=dict)
    normalized_attributes: dict[str, Any] = Field(default_factory=dict)
    scenario_id: str | None = Field(default=None, max_length=80)
    correlation_id: str | None = Field(default=None, max_length=80)

    @field_validator('timestamp', 'observed_at')
    @classmethod
    def utc_time(cls, v):
        if v is None:
            return v
        if v.tzinfo is None:
            raise ValueError('timestamps must include a timezone')
        return v.astimezone(timezone.utc)

    @field_validator('source_ip', 'destination_ip')
    @classmethod
    def valid_ip(cls, v):
        if v is not None:
            return str(ip_address(v))
        return v

    @model_validator(mode='after')
    def bound_json(self):
        """Limit arbitrary event payloads before they reach persistence or processing."""
        if len(json.dumps(self.raw_event, default=str)) > 8192:
            raise ValueError('raw_event exceeds 8192 bytes')
        if len(json.dumps(self.normalized_attributes, default=str)) > 4096:
            raise ValueError('normalized_attributes exceeds 4096 bytes')
        return self

class IncidentPatch(BaseModel):
    """Allow only supported incident lifecycle and assignment changes."""
    status: Literal['open', 'investigating', 'contained', 'resolved', 'false_positive'] | None = None
    severity: Literal['low', 'medium', 'high', 'critical'] | None = None
    assignee: str | None = Field(default=None, max_length=128)
    comment: str | None = Field(default=None, max_length=1000)

class ReplayIn(BaseModel):
    scenario_id: str
    speed: float = Field(default=1.0, ge=0.1, le=100)

class AnalystNote(BaseModel):
    note: str = Field(min_length=1, max_length=1000)
