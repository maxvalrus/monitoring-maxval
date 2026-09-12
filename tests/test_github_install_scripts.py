from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_github_install_script_clones_public_source_and_generates_local_env() -> None:
    script = (ROOT / "scripts" / "install-from-github.sh").read_text(encoding="utf-8")

    assert 'DEFAULT_REPOSITORY="https://github.com/maxvalrus/monitoring-maxval.git"' in script
    assert "MONITORING_GITHUB_TOKEN" not in script
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
