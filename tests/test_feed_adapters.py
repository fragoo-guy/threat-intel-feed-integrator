import asyncio
from typing import Any

import httpx

from app.feeds.abuseipdb import AbuseIPDBAdapter
from app.feeds.otx import OTXAdapter
from app.feeds.virustotal import VirusTotalAdapter


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def test_otx_adapter_maps_pulse_indicators_and_sends_api_key() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-OTX-API-KEY"] == "otx-key"
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "id": "pulse-1",
                        "name": "Phishing pulse",
                        "tags": ["phishing"],
                        "indicators": [{"id": "indicator-1", "indicator": "Example.com", "type": "domain"}],
                    }
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    records = run(OTXAdapter("otx-key", client).fetch())

    assert records[0]["indicator"] == "Example.com"
    assert records[0]["record_id"] == "indicator-1"
    run(client.aclose())


def test_virustotal_adapter_clamps_reputation_to_confidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-apikey"] == "vt-key"
        return httpx.Response(200, json={"data": [{"type": "file", "id": "hash-value", "attributes": {"reputation": -100}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    records = run(VirusTotalAdapter("vt-key", client=client).fetch())

    assert records[0]["confidence_score"] == 0
    run(client.aclose())


def test_abuseipdb_adapter_maps_blacklist_ip() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Key"] == "abuse-key"
        return httpx.Response(200, json={"data": [{"ipAddress": "203.0.113.5", "abuseConfidenceScore": 95}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    records = run(AbuseIPDBAdapter("abuse-key", client=client).fetch())

    assert records[0]["indicator"] == "203.0.113.5"
    assert records[0]["indicator_type"] == "ipv4"
    run(client.aclose())


def test_virustotal_adapter_lookup_indicator_with_stats_and_tags() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-apikey"] == "vt-key"
        assert "/api/v3/files/sample-sha256" in str(request.url)
        return httpx.Response(
            200,
            json={
                "data": {
                    "type": "file",
                    "id": "sample-sha256",
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 60,
                            "suspicious": 10,
                            "harmless": 20,
                            "undetected": 10,
                        },
                        "tags": ["trojan", "ransomware"],
                        "last_modification_date": 1711200000,
                    },
                }
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    record = run(VirusTotalAdapter("vt-key", client=client).lookup_indicator("sample-sha256", endpoint="files"))

    assert record is not None
    assert record["indicator"] == "sample-sha256"
    assert record["confidence_score"] == 70.0
    assert record["threat_tags"] == ["trojan", "ransomware"]
    assert record["last_seen"] == 1711200000
    run(client.aclose())

