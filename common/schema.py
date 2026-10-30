"""The one normalized schema for the whole pipeline.

Every normalized event validates against `Event`; every alert against `Alert`.
On the wire, JSON uses the dotted ECS names as nested objects, e.g.
`{"source": {"ip": "1.2.3.4"}, "@timestamp": "..."}`. That is produced with
`model_dump_json(by_alias=True)` and read back with `model_validate_json(...)`.

Field names, types and the `known_bad` / `unknown` values follow SPEC.md's
"Event and alert schema" section exactly.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

# Fixed namespace so a given (observer.type + raw line) always hashes to the
# same event.id (UUIDv5). A line sent twice gets the same id and is dropped by
# Postgres ON CONFLICT DO NOTHING.
EVENT_ID_NAMESPACE = uuid.UUID("6f4d2c1e-7a3b-5e9f-8c0d-1a2b3c4d5e6f")


def make_event_id(observer_type: str, raw_line: str) -> uuid.UUID:
    """Deterministic UUIDv5 of observer.type + the raw log line."""
    return uuid.uuid5(EVENT_ID_NAMESPACE, f"{observer_type}\n{raw_line}")


# --- nested ECS objects for Event -----------------------------------------
class EventFields(BaseModel):
    """The `event.*` object."""

    id: uuid.UUID
    category: str                       # authentication | web
    action: str                         # ssh_login | http_request
    outcome: str                        # success | failure | unknown
    severity: int                       # 0-100
    original: str                       # the full raw line


class Source(BaseModel):
    ip: str                             # IPv4/IPv6 as a string


class User(BaseModel):
    name: str | None = None


class Url(BaseModel):
    original: str | None = None


class HttpRequest(BaseModel):
    method: str | None = None


class HttpResponse(BaseModel):
    status_code: int | None = None


class Http(BaseModel):
    request: HttpRequest = Field(default_factory=HttpRequest)
    response: HttpResponse = Field(default_factory=HttpResponse)


class UserAgent(BaseModel):
    original: str | None = None


class ThreatIndicator(BaseModel):
    status: str = "unknown"             # known_bad | unknown


class Threat(BaseModel):
    indicator: ThreatIndicator = Field(default_factory=ThreatIndicator)


class Observer(BaseModel):
    type: str                           # ssh | nginx


class Event(BaseModel):
    """A normalized security event. Serialize with by_alias=True."""

    model_config = ConfigDict(populate_by_name=True)

    timestamp: datetime = Field(alias="@timestamp")
    event: EventFields
    source: Source
    observer: Observer
    user: User = Field(default_factory=User)
    url: Url = Field(default_factory=Url)
    http: Http = Field(default_factory=Http)
    user_agent: UserAgent = Field(default_factory=UserAgent)
    threat: Threat = Field(default_factory=Threat)

    def to_json(self) -> str:
        return self.model_dump_json(by_alias=True)

    @classmethod
    def from_json(cls, data: str | bytes) -> "Event":
        return cls.model_validate_json(data)


# --- nested objects for Alert ---------------------------------------------
class AlertRef(BaseModel):
    id: uuid.UUID


class RuleRef(BaseModel):
    id: str


class TechniqueRef(BaseModel):
    id: str                             # T1110.001, T1110.003, T1078


class ThreatTechnique(BaseModel):
    technique: TechniqueRef


class Alert(BaseModel):
    """An alert published to security-alerts and stored in `alerts`."""

    model_config = ConfigDict(populate_by_name=True)

    timestamp: datetime = Field(alias="@timestamp")
    alert: AlertRef
    rule: RuleRef
    threat: ThreatTechnique
    severity: int
    source: Source
    first_seen: datetime
    last_seen: datetime
    event_count: int
    details: dict = Field(default_factory=dict)

    def to_json(self) -> str:
        return self.model_dump_json(by_alias=True)

    @classmethod
    def from_json(cls, data: str | bytes) -> "Alert":
        return cls.model_validate_json(data)
