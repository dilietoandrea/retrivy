import subprocess
import sys
from pathlib import Path

import install_tools
import scan


ROOT_DIR = Path(__file__).resolve().parents[1]


def test_scan_help_runs():
    result = subprocess.run(
        [sys.executable, str(ROOT_DIR / "scan.py"), "--help"],
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
        check=True,
    )

    assert "--scanner" in result.stdout
    assert "--report" in result.stdout


def test_install_tools_help_runs():
    result = subprocess.run(
        [sys.executable, str(ROOT_DIR / "install_tools.py"), "--help"],
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
        check=True,
    )

    assert "--dry-run" in result.stdout
    assert "--force" in result.stdout


def test_install_tool_dry_run_does_not_download(monkeypatch, capsys):
    fake_release = {
        "tag_name": "v1.2.3",
        "assets": [
            {
                "name": "trivy_1.2.3_Linux-64bit.tar.gz",
                "browser_download_url": "https://example.test/trivy.tar.gz",
            }
        ],
    }

    monkeypatch.setattr(install_tools, "latest_release", lambda _repo: fake_release)
    monkeypatch.setattr(install_tools.platform, "system", lambda: "Linux")
    monkeypatch.setattr(install_tools, "normalized_arch", lambda: "amd64")
    monkeypatch.setattr(install_tools, "load_metadata", lambda _tool_name: {})

    def fail_download(*_args, **_kwargs):
        raise AssertionError("dry-run should not download files")

    monkeypatch.setattr(install_tools, "download_file", fail_download)
    monkeypatch.setattr(install_tools, "expected_sha256", lambda *_args: "unused")

    install_tools.install_tool("trivy", dry_run=True)

    output = capsys.readouterr().out
    assert "trivy: ultima release v1.2.3" in output
    assert "Downloading" not in output


def test_run_grype_normalizes_exclude_patterns(monkeypatch, tmp_path):
    captured = {}

    def fake_run(command, cwd, check):
        captured["command"] = command
        captured["cwd"] = cwd
        captured["check"] = check

    monkeypatch.setattr(scan.subprocess, "run", fake_run)

    scan.run_grype(
        Path("grype"),
        ".",
        tmp_path / "grype-results.json",
        [".venv", ".tools", "./already-normalized"],
    )

    command = captured["command"]
    assert captured["cwd"] == scan.ROOT_DIR
    assert captured["check"] is True
    assert command.count("--exclude") == 3
    assert "./.venv" in command
    assert "./.tools" in command
    assert "./already-normalized" in command


def test_ensure_scanner_reports_missing_tool_when_install_disabled(monkeypatch, tmp_path):
    monkeypatch.setattr(scan, "BIN_DIR", tmp_path)

    try:
        scan.ensure_scanner("trivy", no_install=True)
    except RuntimeError as exc:
        assert "python install_tools.py" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError for missing scanner with --no-install")
