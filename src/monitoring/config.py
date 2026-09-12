from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="MONITORING_",
        extra="ignore",
    )

    environment: str = "development"
    database_url: str = "postgresql+psycopg://monitoring:monitoring@db:5432/monitoring"
    secret_key: SecretStr = SecretStr("change-me-before-production")
    allowed_hosts: str = "localhost,127.0.0.1"
    scheduler_enabled: bool = False
    scheduler_poll_seconds: int = Field(default=15, ge=5, le=300)
    default_check_interval_seconds: int = Field(default=300, ge=60, le=86400)
    check_timeout_seconds: float = Field(default=5.0, ge=0.5, le=60)
    max_parallel_checks: int = Field(default=10, ge=1, le=100)
    session_cookie_name: str = "monitoring_session"
    session_cookie_secure: bool | None = None
    session_idle_hours: int = Field(default=8, ge=1, le=8)
    session_max_hours: int = Field(default=24, ge=8, le=24)
    login_max_attempts: int = Field(default=5, ge=3, le=5)
    login_block_minutes: int = Field(default=10, ge=10, le=1440)
    backup_dir: str = "backups"
    tls_manager_url: str = "http://tls-manager:8080"
    http_public_port: int = Field(default=8000, ge=1, le=65535)

    @property
    def allowed_hosts_list(self) -> list[str]:
        return [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.casefold() == "production"

    @property
    def effective_cookie_secure(self) -> bool:
        if self.session_cookie_secure is not None:
            return self.session_cookie_secure
        return self.is_production

    def validate_production(self) -> None:
        uses_default_secret = self.secret_key.get_secret_value() == "change-me-before-production"
        if self.is_production and uses_default_secret:
            raise RuntimeError("MONITORING_SECRET_KEY must be changed in production")


@lru_cache
def get_settings() -> Settings:
    return Settings()
