import os
import subprocess
import sys
import venv
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
VENV_DIR = ROOT_DIR / ".venv"
REQUIREMENTS_FILE = ROOT_DIR / "requirements.txt"
REQUIREMENTS_STAMP = VENV_DIR / ".requirements.stamp"


def venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def run_command(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT_DIR, check=True)


def ensure_virtualenv() -> Path:
    python_path = venv_python()
    if python_path.exists():
        return python_path

    print(f"Creating virtual environment in {VENV_DIR}", flush=True)
    venv.EnvBuilder(with_pip=True).create(VENV_DIR)
    return python_path


def requirements_changed() -> bool:
    if not REQUIREMENTS_FILE.exists():
        return False
    if not REQUIREMENTS_STAMP.exists():
        return True
    return REQUIREMENTS_FILE.stat().st_mtime > REQUIREMENTS_STAMP.stat().st_mtime


def ensure_requirements(python_path: Path) -> None:
    if not REQUIREMENTS_FILE.exists() or not requirements_changed():
        return

    print(f"Installing dependencies from {REQUIREMENTS_FILE.name}", flush=True)
    run_command([
        str(python_path),
        "-m",
        "pip",
        "--disable-pip-version-check",
        "install",
        "-r",
        str(REQUIREMENTS_FILE)
    ])
    REQUIREMENTS_STAMP.touch()


def main() -> int:
    python_path = ensure_virtualenv()
    ensure_requirements(python_path)

    command = [str(python_path), str(ROOT_DIR / "retrivy.py"), *sys.argv[1:]]
    return subprocess.run(command, cwd=ROOT_DIR).returncode


if __name__ == "__main__":
    raise SystemExit(main())
