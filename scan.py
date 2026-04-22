import argparse
import re
import subprocess
from datetime import datetime
from pathlib import Path

import retrivy
from install_tools import BIN_DIR, executable_name, install_tool


ROOT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = ROOT_DIR / "reports"
DEFAULT_SKIP_PATHS = (".venv", ".tools", "__pycache__")


def local_tool_path(scanner: str) -> Path:
    return BIN_DIR / executable_name(scanner)


def ensure_scanner(scanner: str, no_install: bool = False, update_tools: bool = False) -> Path:
    scanner_path = local_tool_path(scanner)

    if update_tools or not scanner_path.exists():
        if no_install:
            raise RuntimeError(
                f"{scanner} non e' installato in {scanner_path}. "
                "Esegui `python install_tools.py` oppure rimuovi --no-install."
            )
        install_tool(scanner, force=update_tools)

    if not scanner_path.exists():
        raise RuntimeError(f"Eseguibile non trovato dopo l'installazione: {scanner_path}")

    return scanner_path


def resolve_output_path(path_value: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        path = ROOT_DIR / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._").lower()
    return slug or "scan"


def target_label(target: str) -> str:
    normalized = str(target).rstrip("\\/")
    if normalized in {"", "."}:
        return ROOT_DIR.name

    parts = re.split(r"[\\/]+", normalized)
    return parts[-1] if parts[-1] else normalized


def timestamp_for_filename() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def default_output_paths(scanner: str, target: str, timestamp: str | None = None) -> tuple[Path, Path]:
    stamp = timestamp or timestamp_for_filename()
    base_name = f"{slugify(target_label(target))}-{scanner}-{stamp}"
    return REPORTS_DIR / f"{base_name}.json", REPORTS_DIR / f"{base_name}.html"


def run_trivy(scanner_path: Path, target: str, json_output: Path, skip_paths: list[str]) -> None:
    command = [
        str(scanner_path),
        "fs",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--output",
        str(json_output),
        "--quiet",
    ]

    for path in skip_paths:
        command.extend(["--skip-dirs", path])

    command.append(target)
    subprocess.run(command, cwd=ROOT_DIR, check=True)


def run_grype(scanner_path: Path, target: str, json_output: Path, skip_paths: list[str]) -> None:
    command = [
        str(scanner_path),
        target,
        "--output",
        "json",
        "--file",
        str(json_output),
        "--quiet",
    ]

    for path in skip_paths:
        if path.startswith(("./", "*/", "**/")):
            pattern = path
        else:
            pattern = f"./{path}"
        command.extend(["--exclude", pattern])

    subprocess.run(command, cwd=ROOT_DIR, check=True)


def run_scan(scanner: str, scanner_path: Path, target: str, json_output: Path, skip_paths: list[str]) -> None:
    if scanner == "trivy":
        run_trivy(scanner_path, target, json_output, skip_paths)
        return

    if scanner == "grype":
        run_grype(scanner_path, target, json_output, skip_paths)
        return

    raise RuntimeError(f"Scanner non supportato: {scanner}")


def generate_report(json_output: Path, report_output: Path) -> None:
    retrivy.main(
        str(json_output),
        str(ROOT_DIR / "css"),
        str(ROOT_DIR / "js"),
        str(report_output),
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Esegue una scansione Trivy/Grype e genera subito il report HTML."
    )
    parser.add_argument(
        "--scanner",
        choices=("trivy", "grype"),
        default="trivy",
        help="Scanner da usare. Default: trivy"
    )
    parser.add_argument(
        "--target",
        default=".",
        help="Percorso o immagine da scansionare. Default: directory corrente"
    )
    parser.add_argument(
        "--report",
        help="Percorso del report HTML da generare. Default: reports/<target>-<scanner>-<timestamp>.html"
    )
    parser.add_argument(
        "--json-output",
        help="Percorso del JSON grezzo dello scanner. Default: reports/<target>-<scanner>-<timestamp>.json"
    )
    parser.add_argument(
        "--no-install",
        action="store_true",
        help="Non installa automaticamente lo scanner se manca."
    )
    parser.add_argument(
        "--update-tools",
        action="store_true",
        help="Aggiorna lo scanner locale all'ultima release prima della scansione."
    )
    parser.add_argument(
        "--include-tool-dirs",
        action="store_true",
        help="Non esclude .venv, .tools e __pycache__ dalla scansione."
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    scanner_path = ensure_scanner(args.scanner, args.no_install, args.update_tools)
    default_json_output, default_report_output = default_output_paths(args.scanner, args.target)
    report_output = resolve_output_path(args.report) if args.report else resolve_output_path(str(default_report_output))
    json_output = resolve_output_path(args.json_output) if args.json_output else resolve_output_path(str(default_json_output))
    skip_paths = [] if args.include_tool_dirs else list(DEFAULT_SKIP_PATHS)

    run_scan(args.scanner, scanner_path, args.target, json_output, skip_paths)
    generate_report(json_output, report_output)

    print(f"JSON generato: {json_output}")
    print(f"Report generato: {report_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
