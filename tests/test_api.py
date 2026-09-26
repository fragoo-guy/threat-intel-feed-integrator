from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.testclient import TestClient

from app.api.deps import get_feed_scheduler, get_ioc_repo
from app.main import app
from app.models.ioc import IOC, IndicatorType, ProviderName, SourceEvidence, ThreatTag


@pytest.fixture
def sample_ioc() -> IOC:
    return IOC(
        indicator="198.51.100.25",
        indicator_type=IndicatorType.IPV4,
        deduplication_key="ipv4:198.51.100.25",
        threat_tags=[ThreatTag.MALWARE, ThreatTag.C2],
        confidence_score=85.0,
        sources=[
            SourceEvidence(
                provider=ProviderName.OTX,
                confidence_score=80.0,
                first_seen=datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc),
                last_seen=datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc),
            ),
            SourceEvidence(
                provider=ProviderName.ABUSEIPDB,
                confidence_score=90.0,
                first_seen=datetime(2026, 9, 19, 8, 0, tzinfo=timezone.utc),
                last_seen=datetime(2026, 9, 23, 14, 0, tzinfo=timezone.utc),
            ),
        ],
        first_seen=datetime(2026, 9, 19, 8, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 9, 23, 14, 0, tzinfo=timezone.utc),
        created_at=datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 9, 23, 14, 0, tzinfo=timezone.utc),
    )


@pytest.fixture
def mock_repo(sample_ioc: IOC) -> MagicMock:
    repo = MagicMock()
    repo.query_iocs = AsyncMock(return_value=[sample_ioc])
    repo.get_by_key = AsyncMock(return_value=sample_ioc)
    repo.get_metrics = AsyncMock(
        return_value={
            "total_iocs": 1,
            "high_confidence_count": 1,
            "by_indicator_type": {"ipv4": 1},
            "by_threat_tag": {"malware": 1, "c2": 1},
            "by_provider": {"otx": 1, "abuseipdb": 1},
        }
    )
    return repo


@pytest.fixture
def mock_scheduler() -> MagicMock:
    scheduler = MagicMock()
    scheduler.run_feed_now = AsyncMock(
        return_value={
            "provider": "otx",
            "status": "success",
            "records_fetched": 10,
            "records_upserted": 10,
            "errors": 0,
        }
    )
    return scheduler


@pytest.fixture
def client(mock_repo: MagicMock, mock_scheduler: MagicMock) -> TestClient:
    app.dependency_overrides[get_ioc_repo] = lambda: mock_repo
    app.dependency_overrides[get_feed_scheduler] = lambda: mock_scheduler
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_root_endpoint(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "/docs" in data["docs"]


def test_health_endpoints(client: TestClient) -> None:
    res1 = client.get("/health")
    assert res1.status_code == 200
    assert res1.json()["status"] == "ok"

    res2 = client.get("/api/v1/health")
    assert res2.status_code == 200
    assert res2.json()["status"] == "ok"
    assert "feeds" in res2.json()


def test_get_metrics(client: TestClient) -> None:
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    data = response.json()
    assert data["total_iocs"] == 1
    assert data["high_confidence_count"] == 1
    assert data["by_indicator_type"]["ipv4"] == 1


def test_list_iocs_with_filters(client: TestClient, mock_repo: MagicMock) -> None:
    response = client.get(
        "/api/v1/iocs",
        params={
            "indicator": "198.51",
            "indicator_type": "ipv4",
            "tag": "malware",
            "provider": "otx",
            "min_confidence": 75.0,
            "limit": 20,
            "skip": 0,
        },
    )
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 1
    assert items[0]["indicator"] == "198.51.100.25"
    assert items[0]["deduplication_key"] == "ipv4:198.51.100.25"
    mock_repo.query_iocs.assert_called_once()


def test_get_ioc_detail_found(client: TestClient) -> None:
    response = client.get("/api/v1/iocs/ipv4:198.51.100.25")
    assert response.status_code == 200
    data = response.json()
    assert data["indicator"] == "198.51.100.25"
    assert len(data["sources"]) == 2


def test_get_ioc_detail_not_found(client: TestClient, mock_repo: MagicMock) -> None:
    mock_repo.get_by_key = AsyncMock(return_value=None)
    response = client.get("/api/v1/iocs/ipv4:999.999.999.999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


def test_trigger_feed_sync_valid(client: TestClient, mock_scheduler: MagicMock) -> None:
    response = client.post("/api/v1/feeds/otx/sync")
    assert response.status_code == 200
    data = response.json()
    assert data["provider"] == "otx"
    assert data["result"]["status"] == "success"
    mock_scheduler.run_feed_now.assert_called_once_with("otx")


def test_trigger_feed_sync_invalid_provider(client: TestClient) -> None:
    response = client.post("/api/v1/feeds/unsupported_vendor/sync")
    assert response.status_code == 400
    assert "Invalid provider" in response.json()["detail"]


def test_export_csv(client: TestClient) -> None:
    response = client.get("/api/v1/export/csv?indicator_type=ipv4")
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "attachment; filename=" in response.headers["content-disposition"]
    text = response.text
    assert "indicator,indicator_type,threat_tags" in text
    assert "198.51.100.25,ipv4" in text


def test_export_stix(client: TestClient) -> None:
    response = client.get("/api/v1/export/stix?tag=malware")
    assert response.status_code == 200
    assert "application/json" in response.headers["content-type"]
    assert "stix2_bundle.json" in response.headers["content-disposition"]
    bundle = response.json()
    assert bundle["type"] == "bundle"
    assert "objects" in bundle
    assert len(bundle["objects"]) == 1
    assert bundle["objects"][0]["type"] == "indicator"
    assert "ipv4-addr:value = '198.51.100.25'" in bundle["objects"][0]["pattern"]
