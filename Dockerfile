FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml ./
COPY constraints.txt ./
COPY app ./app

# Keep build-time package and browser downloads on the same egress path as runtime traffic.
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG ALL_PROXY
ARG NO_PROXY

RUN pip install --upgrade pip && pip install -c constraints.txt ".[browser]" \
    && python -m playwright install --with-deps chromium

RUN mkdir -p /data /backups

EXPOSE 1455

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "1455"]
