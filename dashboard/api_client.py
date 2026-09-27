import os
from typing import Any
import requests


class ThreatIntelAPIClient:
    """HTTP client communicating with the FastAPI backend for SOC dashboard queries."""

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("API_URL", "http://127.0.0.1:8000")).rstrip("/")
        self.timeout = 10.0

    def check_connection(self) -> bool:
        """Check if the FastAPI backend is online and reachable."""
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=self.timeout)
            return resp.status_code == 200
        except Exception:
            return False

    def get_health(self) -> dict[str, Any] | None:
        """Fetch system and threat feed health status."""
        try:
            resp = requests.get(f"{self.base_url}/api/v1/health", timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def get_metrics(self) -> dict[str, Any] | None:
        """Fetch high-level aggregate SOC metrics from the backend."""
        try:
            resp = requests.get(f"{self.base_url}/api/v1/metrics", timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def query_iocs(
        self,
        indicator: str | None = None,
        indicator_type: str | None = None,
        tag: str | None = None,
        provider: str | None = None,
        min_confidence: float | None = None,
        limit: int = 50,
        skip: int = 0,
    ) -> list[dict[str, Any]]:
        """Fetch filtered and paginated IOC records."""
        params: dict[str, Any] = {"limit": limit, "skip": skip}
        if indicator:
            params["indicator"] = indicator.strip()
        if indicator_type:
            params["indicator_type"] = indicator_type
        if tag:
            params["tag"] = tag
        if provider:
            params["provider"] = provider
        if min_confidence is not None:
            params["min_confidence"] = float(min_confidence)

        try:
            resp = requests.get(f"{self.base_url}/api/v1/iocs", params=params, timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return []

    def get_ioc_detail(self, deduplication_key: str) -> dict[str, Any] | None:
        """Fetch in-depth details for a single IOC by deduplication key."""
        try:
            resp = requests.get(f"{self.base_url}/api/v1/iocs/{deduplication_key}", timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def trigger_sync(self, provider: str) -> dict[str, Any] | None:
        """Trigger an on-demand feed ingestion sync."""
        try:
            resp = requests.post(f"{self.base_url}/api/v1/feeds/{provider.lower()}/sync", timeout=30.0)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def get_csv_export(
        self,
        indicator: str | None = None,
        indicator_type: str | None = None,
        tag: str | None = None,
        provider: str | None = None,
        min_confidence: float | None = None,
    ) -> str | None:
        """Fetch CSV export content for the current filter."""
        params: dict[str, Any] = {}
        if indicator:
            params["indicator"] = indicator
        if indicator_type:
            params["indicator_type"] = indicator_type
        if tag:
            params["tag"] = tag
        if provider:
            params["provider"] = provider
        if min_confidence is not None:
            params["min_confidence"] = float(min_confidence)

        try:
            resp = requests.get(f"{self.base_url}/api/v1/export/csv", params=params, timeout=self.timeout)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None

    def get_stix_export(
        self,
        indicator: str | None = None,
        indicator_type: str | None = None,
        tag: str | None = None,
        provider: str | None = None,
        min_confidence: float | None = None,
    ) -> dict[str, Any] | None:
        """Fetch STIX 2.1 JSON bundle export for the current filter."""
        params: dict[str, Any] = {}
        if indicator:
            params["indicator"] = indicator
        if indicator_type:
            params["indicator_type"] = indicator_type
        if tag:
            params["tag"] = tag
        if provider:
            params["provider"] = provider
        if min_confidence is not None:
            params["min_confidence"] = float(min_confidence)

        try:
            resp = requests.get(f"{self.base_url}/api/v1/export/stix", params=params, timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None
