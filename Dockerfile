# Sleuth — local-LLM web + recon toolkit, containerised.
# The LLM (LM Studio / Ollama) stays on the host and is reached via
# host.docker.internal; ZAP runs as a sibling container (see compose).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SLEUTH_IN_DOCKER=1

WORKDIR /app

# adb client talks to a host emulator/device (see SLEUTH_ADB_HOST in compose).
RUN apt-get update \
    && apt-get install -y --no-install-recommends android-tools-adb ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python deps first, for layer caching. wapiti3 (the free scanner) is included
# so the container is batteries-included.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt wapiti3

# Application code (no .env or data — those come in at runtime via compose).
COPY websearch ./websearch
COPY run_server.py selftest.py install.py ./

EXPOSE 8765

# Bind to 0.0.0.0 so the published port works; the host still maps it to
# 127.0.0.1 only (see docker-compose.yml).
CMD ["python", "-m", "websearch.webchat", "--host", "0.0.0.0", "--port", "8765"]
