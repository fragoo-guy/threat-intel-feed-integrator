from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILE_NAME = "file_name"


class ThreatTag(StrEnum):
    MALWARE = "malware"
    PHISHING = "phishing"
    C2 = "c2"
    BOTNET = "botnet"
    EXPLOIT = "exploit"
    SUSPICIOUS = "suspicious"


class ProviderName(StrEnum):
    OTX = "otx"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    MISP_FIXTURE = "misp_fixture"


class SourceEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: ProviderName
    record_id: str | None = None
    source_url: str | None = None
    confidence_score: float | None = Field(default=None, ge=0, le=100)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class IOC(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: str = Field(min_length=1)
    indicator_type: IndicatorType
    deduplication_key: str = Field(min_length=3)
    threat_tags: list[ThreatTag] = Field(default_factory=list)
    confidence_score: float = Field(ge=0, le=100)
    sources: list[SourceEvidence] = Field(min_length=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("indicator", mode="before")
    @classmethod
    def strip_indicator(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("indicator must be a string")
        return value.strip()

    @field_validator("deduplication_key", mode="before")
    @classmethod
    def normalize_deduplication_key(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("deduplication_key must be a string")
        return value.strip().lower()

    @model_validator(mode="after")
    def validate_consistency(self) -> "IOC":
        expected_key = f"{self.indicator_type.value}:{self.indicator.lower()}"
        if self.deduplication_key != expected_key:
            raise ValueError("deduplication_key must match indicator type and indicator")
        if self.first_seen and self.last_seen and self.first_seen > self.last_seen:
            raise ValueError("first_seen cannot be later than last_seen")
        if self.created_at.tzinfo is None or self.updated_at.tzinfo is None:
            raise ValueError("created_at and updated_at must be timezone-aware")
        return self
