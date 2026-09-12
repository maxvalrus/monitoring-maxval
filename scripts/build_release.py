"""Build a clean, self-contained Monitoring Maxval release archive."""

from __future__ import annotations

import argparse
import secrets
import shutil
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CADDYFILE = """{
  auto_https off
  admin 0.0.0.0:2019
}

:80 {
  reverse_proxy app:8000
}
"""
TOP_LEVEL_FILES = (
    "AGENTS.md",
    "CHANGELOG.md",
    "Dockerfile",
    "PROJECT.md",
    "README.md",
    "alembic.ini",
    "compose.yaml",
    "env.example",
    "pyproject.toml",
    "requirements.lock",
    ".gitignore",
)
DIRECTORIES = ("alembic", "docs", "scripts", "src", "tls-manager", "tests")
FORBIDDEN_PARTS = (".git", ".agents", ".codex", "__pycache__", "patchfromchat", "releases", "tls")


def ignored_release_file(directory: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        if name in FORBIDDEN_PARTS or name.endswith((".egg-info", ".pyc", ".pyo")):
            ignored.add(name)
    return ignored


def release_env() -> str:
    password = secrets.token_urlsafe(32)
    secret_key = secrets.token_urlsafe(48)
    database_url = f"postgresql+psycopg://monitoring:{password}@db:5432/monitoring"
    return "\n".join(
        (
            "MONITORING_ENVIRONMENT=production",
            f"MONITORING_DATABASE_URL={database_url}",
            f"MONITORING_SECRET_KEY={secret_key}",
            "MONITORING_ALLOWED_HOSTS=*",
            "MONITORING_SCHEDULER_ENABLED=true",
            "MONITORING_SESSION_COOKIE_SECURE=false",
            "POSTGRES_DB=monitoring",
            "POSTGRES_USER=monitoring",
            f"POSTGRES_PASSWORD={password}",
            "POSTGRES_VOLUME_NAME=monitoring-maxval_postgres_data",
            "BACKUP_VOLUME_NAME=monitoring-maxval_backup_data",
            "",
        )
    )


def copy_release_tree(destination: Path, version: str) -> None:
    for filename in TOP_LEVEL_FILES:
        shutil.copy2(ROOT / filename, destination / filename)
    instruction = f"INSTRUCTION_{version}.txt"
    shutil.copy2(ROOT / instruction, destination / instruction)
    for directory in DIRECTORIES:
        shutil.copytree(
            ROOT / directory,
            destination / directory,
            ignore=ignored_release_file,
        )
    release_notes = destination / "docs" / "releases"
    if release_notes.exists():
        shutil.rmtree(release_notes)
    release_notes.mkdir()
    shutil.copy2(
        ROOT / "docs" / "releases" / f"{version}.md",
        release_notes / f"{version}.md",
    )
    caddy_directory = destination / "caddy"
    caddy_directory.mkdir()
    (caddy_directory / "Caddyfile").write_text(DEFAULT_CADDYFILE, encoding="utf-8")
    env_file = destination / ".env"
    env_file.write_text(release_env(), encoding="utf-8")
    env_file.chmod(0o600)


def validate_archive(archive: Path, prefix: str, version: str) -> None:
    forbidden_names = (
        ".git/",
        ".agents/",
        ".codex/",
        "__pycache__",
        ".egg-info/",
        "patchfromchat/",
        ".pyc",
        "/tls/",
    )
    expected_instruction = f"{prefix}/INSTRUCTION_{version}.txt"
    expected_release_note = f"{prefix}/docs/releases/{version}.md"
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        assert f"{prefix}/.env" in names
        assert f"{prefix}/caddy/Caddyfile" in names
        assert not any(any(part in name for part in forbidden_names) for name in names)
        instructions = [name for name in names if Path(name).name.startswith("INSTRUCTION_")]
        assert instructions == [expected_instruction]
        release_notes = [name for name in names if "/docs/releases/" in name]
        assert release_notes == [expected_release_note]
        assert package.read(f"{prefix}/caddy/Caddyfile").decode() == DEFAULT_CADDYFILE


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="release version, for example 0.8.5")
    args = parser.parse_args()
    prefix = f"monitoring-maxval-{args.version}"
    destination = ROOT / "releases" / f"{prefix}.zip"
    destination.parent.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="monitoring-maxval-release-") as temporary:
        staging = Path(temporary) / prefix
        staging.mkdir()
        copy_release_tree(staging, args.version)
        candidate = destination.with_suffix(".zip.tmp")
        candidate.unlink(missing_ok=True)
        with zipfile.ZipFile(candidate, "w", compression=zipfile.ZIP_DEFLATED) as package:
            for path in sorted(staging.rglob("*")):
                if path.is_file():
                    package.write(path, path.relative_to(staging.parent))
        validate_archive(candidate, prefix, args.version)
        candidate.replace(destination)
    print(destination)


if __name__ == "__main__":
    main()
