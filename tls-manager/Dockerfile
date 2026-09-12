FROM caddy:2.8.4-alpine

RUN apk add --no-cache python3 py3-pip openssl

COPY tls-manager/requirements.lock /tmp/tls-manager-requirements.lock
RUN pip install --no-cache-dir --break-system-packages \
    -r /tmp/tls-manager-requirements.lock \
    && rm /tmp/tls-manager-requirements.lock

COPY tls-manager/app.py /srv/tls-manager/app.py

CMD ["python3", "-m", "uvicorn", "app:app", "--app-dir", "/srv/tls-manager", "--host", "0.0.0.0", "--port", "8080"]
