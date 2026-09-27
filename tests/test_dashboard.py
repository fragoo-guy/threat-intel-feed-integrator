from unittest.mock import MagicMock, patch

from dashboard.api_client import ThreatIntelAPIClient
from dashboard.mitre import generate_suricata_rule, get_mitre_context


def test_client_check_connection_success() -> None:
    client = ThreatIntelAPIClient("http://testserver")
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("requests.get", return_value=mock_resp):
        assert client.check_connection() is True


def test_client_check_connection_failure() -> None:
    client = ThreatIntelAPIClient("http://testserver")
    with patch("requests.get", side_effect=Exception("Connection refused")):
        assert client.check_connection() is False


def test_client_get_health_success() -> None:
    client = ThreatIntelAPIClient("http://testserver")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "ok", "feeds": {}}

    with patch("requests.get", return_value=mock_resp):
        health = client.get_health()
        assert health is not None
        assert health["status"] == "ok"


def test_client_get_metrics_success() -> None:
    client = ThreatIntelAPIClient("http://testserver")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"total_iocs": 42, "high_confidence_count": 10}

    with patch("requests.get", return_value=mock_resp):
        metrics = client.get_metrics()
        assert metrics is not None
        assert metrics["total_iocs"] == 42


def test_client_query_iocs() -> None:
    client = ThreatIntelAPIClient("http://testserver")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{"indicator": "198.51.100.1", "indicator_type": "ipv4"}]

    with patch("requests.get", return_value=mock_resp) as mock_get:
        iocs = client.query_iocs(indicator="198.51", indicator_type="ipv4", min_confidence=50)
        assert len(iocs) == 1
        assert iocs[0]["indicator"] == "198.51.100.1"
        mock_get.assert_called_once()
        called_params = mock_get.call_args[1]["params"]
        assert called_params["indicator"] == "198.51"
        assert called_params["min_confidence"] == 50.0


def test_client_trigger_sync() -> None:
    client = ThreatIntelAPIClient("http://testserver")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"provider": "otx", "result": {"status": "success"}}

    with patch("requests.post", return_value=mock_resp):
        res = client.trigger_sync("otx")
        assert res is not None
        assert res["provider"] == "otx"


def test_client_exports() -> None:
    client = ThreatIntelAPIClient("http://testserver")
    mock_csv_resp = MagicMock()
    mock_csv_resp.status_code = 200
    mock_csv_resp.text = "indicator,indicator_type\n198.51.100.1,ipv4"

    with patch("requests.get", return_value=mock_csv_resp):
        csv_data = client.get_csv_export()
        assert "indicator,indicator_type" in csv_data

    mock_stix_resp = MagicMock()
    mock_stix_resp.status_code = 200
    mock_stix_resp.json.return_value = {"type": "bundle", "objects": []}

    with patch("requests.get", return_value=mock_stix_resp):
        stix_data = client.get_stix_export()
        assert stix_data["type"] == "bundle"


def test_mitre_mapping_known_tags() -> None:
    results = get_mitre_context(["c2", "phishing", "unknown_tag"])
    assert len(results) == 2
    tech_ids = [r["technique_id"] for r in results]
    assert "T1071" in tech_ids
    assert "T1566" in tech_ids


def test_generate_suricata_rule_ipv4() -> None:
    ioc = {
        "indicator": "198.51.100.5",
        "indicator_type": "ipv4",
        "threat_tags": ["c2", "malware"],
        "confidence_score": 90,
    }
    rule = generate_suricata_rule(ioc, sid_base=1000001)
    assert 'alert ip any any -> [198.51.100.5] any' in rule
    assert 'sid:1000001' in rule
    assert 'classtype:trojan-activity' in rule


def test_generate_suricata_rule_domain() -> None:
    ioc = {
        "indicator": "malicious-c2.com",
        "indicator_type": "domain",
        "threat_tags": ["c2"],
        "confidence_score": 85,
    }
    rule = generate_suricata_rule(ioc, sid_base=1000002)
    assert 'alert dns any any -> any any' in rule
    assert 'content:"malicious-c2.com"' in rule
    assert 'sid:1000002' in rule
