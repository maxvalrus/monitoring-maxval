from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from monitoring.db import Base
from monitoring.models.mixins import TimestampMixin


class AppSetting(TimestampMixin, Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(String(500))
