FROM python:3.12.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system monitoring && adduser --system --ingroup monitoring monitoring \
    && mkdir -p /app/backups && chown monitoring:monitoring /app/backups

COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

COPY pyproject.toml README.md ./
COPY alembic.ini ./
COPY alembic ./alembic
COPY scripts ./scripts
COPY src ./src

RUN pip install --no-cache-dir --no-deps .

USER monitoring

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn monitoring.main:app --host 0.0.0.0 --port 8000 --workers 1 --proxy-headers --forwarded-allow-ips=*"]
