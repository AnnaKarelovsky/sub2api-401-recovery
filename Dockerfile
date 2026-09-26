ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml ./
COPY constraints.txt ./

# Keep build-time package and browser downloads on the same egress path as runtime traffic.
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG ALL_PROXY
ARG NO_PROXY
ARG INSTALL_BROWSER_DEPS=1

RUN pip install --upgrade pip \
    && pip install -c constraints.txt "playwright>=1.48,<2.0"

RUN if [ "$INSTALL_BROWSER_DEPS" = "1" ]; then python -m playwright install-deps chromium; fi
RUN python -m playwright install chromium

COPY app ./app
RUN pip install -c constraints.txt ".[browser]"

RUN mkdir -p /data /backups

EXPOSE 1455

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "1455"]
