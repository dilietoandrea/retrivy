import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = ROOT_DIR / ".tools"
BIN_DIR = TOOLS_DIR / "bin"
CACHE_DIR = TOOLS_DIR / "cache"

USER_AGENT = "retrivy-tool-installer"


TOOL_CONFIG = {
    "trivy": {
        "repo": "aquasecurity/trivy",
        "executable": "trivy",
        "assets": {
            ("Windows", "amd64"): "trivy_{version}_windows-64bit.zip",
            ("Linux", "amd64"): "trivy_{version}_Linux-64bit.tar.gz",
            ("Linux", "arm64"): "trivy_{version}_Linux-ARM64.tar.gz",
            ("Darwin", "amd64"): "trivy_{version}_macOS-64bit.tar.gz",
            ("Darwin", "arm64"): "trivy_{version}_macOS-ARM64.tar.gz",
        },
    },
    "grype": {
        "repo": "anchore/grype",
        "executable": "grype",
        "assets": {
            ("Windows", "amd64"): "grype_{version}_windows_amd64.zip",
            ("Linux", "amd64"): "grype_{version}_linux_amd64.tar.gz",
            ("Linux", "arm64"): "grype_{version}_linux_arm64.tar.gz",
            ("Darwin", "amd64"): "grype_{version}_darwin_amd64.tar.gz",
            ("Darwin", "arm64"): "grype_{version}_darwin_arm64.tar.gz",
        },
    },
}


def normalized_arch() -> str:
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        return "amd64"
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    return machine


def executable_name(tool_name: str) -> str:
    suffix = ".exe" if os.name == "nt" else ""
    return f"{TOOL_CONFIG[tool_name]['executable']}{suffix}"


def request_json(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def download_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request) as response:
        return response.read().decode("utf-8")


def download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request) as response, destination.open("wb") as file:
        shutil.copyfileobj(response, file)


def find_asset(release: dict, asset_name: str) -> dict:
    for asset in release.get("assets", []):
        if asset.get("name") == asset_name:
            return asset
    raise RuntimeError(f"Asset non trovato nella release: {asset_name}")


def latest_release(repo: str) -> dict:
    return request_json(f"https://api.github.com/repos/{repo}/releases/latest")


def expected_asset_name(tool_name: str, version: str) -> str:
    system = platform.system()
    arch = normalized_arch()
    template = TOOL_CONFIG[tool_name]["assets"].get((system, arch))
    if not template:
        raise RuntimeError(f"Piattaforma non supportata per {tool_name}: {system}/{arch}")
    return template.format(version=version)


def expected_sha256(release: dict, asset_name: str) -> str:
    checksum_asset = next(
        (
            asset for asset in release.get("assets", [])
            if asset.get("name", "").endswith("_checksums.txt")
        ),
        None,
    )
    if not checksum_asset:
        raise RuntimeError("File checksums.txt non trovato nella release.")

    checksum_text = download_text(checksum_asset["browser_download_url"])
    for line in checksum_text.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2 and Path(parts[1]).name == asset_name:
            return parts[0].lower()

    raise RuntimeError(f"Checksum non trovato per asset: {asset_name}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum(path: Path, expected_hash: str) -> None:
    actual_hash = sha256_file(path)
    if actual_hash != expected_hash:
        raise RuntimeError(
            f"Checksum non valido per {path.name}: atteso {expected_hash}, trovato {actual_hash}"
        )


def safe_extract_zip(archive_path: Path, destination: Path) -> None:
    destination = destination.resolve()
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            target_path = (destination / member.filename).resolve()
            if destination not in target_path.parents and target_path != destination:
                raise RuntimeError(f"Percorso non sicuro nell'archivio: {member.filename}")
        archive.extractall(destination)


def safe_extract_tar(archive_path: Path, destination: Path) -> None:
    destination = destination.resolve()
    with tarfile.open(archive_path) as archive:
        for member in archive.getmembers():
            target_path = (destination / member.name).resolve()
            if destination not in target_path.parents and target_path != destination:
                raise RuntimeError(f"Percorso non sicuro nell'archivio: {member.name}")
        archive.extractall(destination)


def extract_archive(archive_path: Path, destination: Path) -> None:
    if archive_path.suffix == ".zip":
        safe_extract_zip(archive_path, destination)
        return

    if archive_path.name.endswith(".tar.gz"):
        safe_extract_tar(archive_path, destination)
        return

    raise RuntimeError(f"Formato archivio non supportato: {archive_path.name}")


def find_executable(directory: Path, executable: str) -> Path:
    matches = [path for path in directory.rglob(executable) if path.is_file()]
    if not matches:
        raise RuntimeError(f"Eseguibile non trovato nell'archivio: {executable}")
    return matches[0]


def metadata_path(tool_name: str) -> Path:
    return TOOLS_DIR / f"{tool_name}.json"


def load_metadata(tool_name: str) -> dict:
    path = metadata_path(tool_name)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_metadata(tool_name: str, metadata: dict) -> None:
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    metadata_path(tool_name).write_text(
        json.dumps(metadata, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def install_tool(tool_name: str, force: bool = False, dry_run: bool = False) -> None:
    config = TOOL_CONFIG[tool_name]
    release = latest_release(config["repo"])
    version = release["tag_name"].lstrip("v")
    asset_name = expected_asset_name(tool_name, version)
    asset = find_asset(release, asset_name)
    target_executable = BIN_DIR / executable_name(tool_name)
    existing = load_metadata(tool_name)

    if (
        not force
        and target_executable.exists()
        and existing.get("version") == release["tag_name"]
    ):
        print(f"{tool_name} {release['tag_name']} gia' installato in {target_executable}")
        return

    print(f"{tool_name}: ultima release {release['tag_name']} -> {asset_name}")
    if dry_run:
        return

    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    archive_path = CACHE_DIR / asset_name
    expected_hash = expected_sha256(release, asset_name)

    print(f"Downloading {asset_name}")
    download_file(asset["browser_download_url"], archive_path)
    verify_checksum(archive_path, expected_hash)
    print(f"Checksum OK: {expected_hash}")

    with tempfile.TemporaryDirectory() as temp_dir:
        extract_dir = Path(temp_dir)
        extract_archive(archive_path, extract_dir)
        extracted_executable = find_executable(extract_dir, executable_name(tool_name))
        shutil.copy2(extracted_executable, target_executable)

    if os.name != "nt":
        mode = target_executable.stat().st_mode
        target_executable.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    write_metadata(tool_name, {
        "asset": asset_name,
        "repository": config["repo"],
        "sha256": expected_hash,
        "url": asset["browser_download_url"],
        "version": release["tag_name"],
    })
    print(f"Installato: {target_executable}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Installa Trivy e Grype localmente nella cartella .tools del progetto."
    )
    parser.add_argument(
        "tools",
        nargs="*",
        choices=sorted(TOOL_CONFIG),
        help="Tool da installare. Default: trivy grype"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Reinstalla anche se la versione piu' recente e' gia' presente."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Mostra cosa verrebbe installato senza scaricare gli archivi."
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    selected_tools = args.tools or sorted(TOOL_CONFIG)

    for tool_name in selected_tools:
        install_tool(tool_name, force=args.force, dry_run=args.dry_run)

    print(f"\nEseguibili disponibili in: {BIN_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
