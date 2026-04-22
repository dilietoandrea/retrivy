import json

import pytest

import retrivy


def test_parse_trivy_json_normalizes_vulnerabilities():
    data = {
        "CreatedAt": "2026-04-22T19:00:00.123456789+02:00",
        "Results": [
            {
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "PkgName": "flask",
                        "PkgIdentifier": {"PURL": "pkg:pypi/flask@0.5"},
                        "VulnerabilityID": "CVE-0000-0001",
                        "Severity": "high",
                        "InstalledVersion": "0.5",
                        "FixedVersion": "2.0.0",
                        "PrimaryURL": "https://example.test/cve",
                        "References": ["https://example.test/ref"],
                        "Title": "Example vulnerability",
                    }
                ],
            }
        ],
    }

    results = retrivy.parse_trivy_json(data)

    vulnerabilities, target, analysis_type, created_at = results[0]
    assert target == "requirements.txt"
    assert analysis_type == "pip"
    assert created_at == data["CreatedAt"]
    assert vulnerabilities[0]["PkgName"] == "flask"
    assert vulnerabilities[0]["PURL"] == "pkg:pypi/flask@0.5"
    assert vulnerabilities[0]["Severity"] == "HIGH"


def test_parse_trivy_json_handles_metadata_only_report():
    data = {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.70.0"},
        "CreatedAt": "2026-04-22T19:00:00Z",
        "ArtifactName": "input examples/classifica-film-2.8.0",
        "ArtifactType": "filesystem",
    }

    results = retrivy.parse_trivy_json(data)

    vulnerabilities, target, analysis_type, created_at = results[0]
    assert vulnerabilities == []
    assert target == "input examples/classifica-film-2.8.0"
    assert analysis_type == "filesystem"
    assert created_at == "2026-04-22T19:00:00Z"


def test_parse_grype_json_groups_vulnerabilities_by_location():
    data = {
        "descriptor": {"timestamp": "2026-04-22T19:00:00Z"},
        "matches": [
            {
                "artifact": {
                    "name": "cryptography",
                    "version": "41.0.2",
                    "type": "python",
                    "purl": "pkg:pypi/cryptography@41.0.2",
                    "locations": [{"path": "requirements.txt"}],
                },
                "relatedVulnerabilities": [
                    {
                        "id": "CVE-0000-0002",
                        "severity": "critical",
                        "fix": {"versions": ["42.0.0"]},
                        "dataSource": "https://example.test/cve",
                        "urls": ["https://example.test/ref"],
                        "description": "Critical issue",
                    }
                ],
            }
        ],
    }

    results = retrivy.parse_grype_json(data)

    vulnerabilities, target, analysis_type, created_at = results[0]
    assert target == "requirements.txt"
    assert analysis_type == "python"
    assert created_at == "2026-04-22T19:00:00Z"
    assert vulnerabilities[0]["VulnerabilityID"] == "CVE-0000-0002"
    assert vulnerabilities[0]["Severity"] == "CRITICAL"
    assert vulnerabilities[0]["FixedVersion"] == "42.0.0"


def test_generate_table_rows_escapes_html_and_blocks_unsafe_links():
    rows = retrivy.generate_table_rows([
        {
            "PkgName": "<script>alert(1)</script>",
            "PURL": "pkg:test/<bad>",
            "VulnerabilityID": "CVE-0000-0003",
            "Severity": "medium",
            "InstalledVersion": "1.0",
            "FixedVersion": "1.1",
            "Title": "<img src=x onerror=alert(1)>",
            "PrimaryURL": "javascript:alert(1)",
            "References": [
                "https://example.test/advisory",
                "javascript:alert(2)",
            ],
        }
    ])

    assert "<script>" not in rows
    assert "<img" not in rows
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rows
    assert "&lt;img src=x onerror=alert(1)&gt;" in rows
    assert 'href="javascript:alert(1)"' not in rows
    assert 'href="#"' in rows
    assert 'href="https://example.test/advisory"' in rows


def test_format_date_truncates_nanoseconds():
    assert retrivy.format_date("2026-04-22T19:00:00.123456789+02:00") == "2026-04-22 19:00:00"


def test_read_json_input_falls_back_to_utf8_when_detector_reports_ascii(tmp_path, monkeypatch):
    class FakeChardet:
        @staticmethod
        def detect(_raw_data):
            return {"encoding": "ascii"}

    payload = {
        "CreatedAt": "2026-04-22T19:00:00Z",
        "Results": [
            {
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "PkgName": "demo",
                        "VulnerabilityID": "CVE-0000-0004",
                        "Severity": "LOW",
                        "Title": "vulnerabilita accentata",
                        "PrimaryURL": "https://example.test/cve",
                    }
                ],
            }
        ],
    }
    input_file = tmp_path / "results.json"
    input_file.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(retrivy, "chardet", FakeChardet)

    results, scanner = retrivy.read_json_input(str(input_file))

    assert scanner == "Trivy"
    assert results[0][0][0]["Title"] == "vulnerabilita accentata"


def test_read_json_input_rejects_unknown_format(tmp_path):
    input_file = tmp_path / "unknown.json"
    input_file.write_text('{"not": "a scanner result"}', encoding="utf-8")

    with pytest.raises(ValueError, match="Formato JSON non riconosciuto"):
        retrivy.read_json_input(str(input_file))
