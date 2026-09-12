from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_github_install_script_clones_public_source_and_generates_local_env() -> None:
    script = (ROOT / "scripts" / "install-from-github.sh").read_text(encoding="utf-8")

    assert 'DEFAULT_REPOSITORY="https://github.com/maxvalrus/monitoring-maxval.git"' in script
    assert "MONITORING_GITHUB_TOKEN" not in script
    assert "install_host_dependencies" in script
    assert "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin" in script
    assert "debian|ubuntu)" in script
    assert "linuxmint)" in script
    assert "docker_distribution='ubuntu'" in script
    assert "download.docker.com/linux/${docker_distribution}/gpg" in script
    assert "UBUNTU_CODENAME" in script
    assert "MONITORING_DATABASE_URL=postgresql+psycopg://monitoring:${database_password}@db:5432/monitoring" in script
    assert "install -m 600 \"$install_dir/caddy/Caddyfile.example\"" in script
    assert "seed_demo.py" in script
    assert "docker volume inspect monitoring-maxval_postgres_data" in script
    assert "docker compose config >/dev/null" in script
    assert "docker compose down -v" not in script


def test_github_update_script_preserves_runtime_and_requires_safe_update() -> None:
    script = (ROOT / "scripts" / "update-from-github.sh").read_text(encoding="utf-8")

    assert "./scripts/backup_database.sh" in script
    assert "git status --porcelain --untracked-files=no" in script
    assert "git merge --ff-only" in script
    assert "docker compose exec -T app alembic upgrade head" in script
    assert "docker compose down -v" not in script
    assert "MONITORING_GITHUB_TOKEN" not in script
    assert "cleanup() {\n    :\n}" in script
    assert "MONITORING_PROJECT_DIR" in script


def test_uninstall_script_requires_separate_confirmation_for_runtime_data() -> None:
    script = (ROOT / "scripts" / "uninstall.sh").read_text(encoding="utf-8")

    assert "docker compose down --remove-orphans" in script
    assert "docker compose down --remove-orphans --volumes" in script
    assert "DELETE DATA" in script
    assert "DELETE TLS" in script
    assert "DELETE PROJECT" in script
    assert "rm -rf --one-file-system \"$project_dir/tls\"" in script
    assert "rm -rf --one-file-system \"$project_dir\"" in script
