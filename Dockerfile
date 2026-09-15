FROM python:3.11-slim

LABEL maintainer="Sinduk Team"
LABEL description="Self-Hosted Zero-Knowledge Team Secrets & Vault Sync Server"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files and install
COPY pyproject.toml README.md LICENSE /app/
COPY sinduk /app/sinduk
RUN pip install --no-cache-dir .

# Create volume mount point for server DB and state
ENV HOME=/data
ENV SINDUK_HOST=0.0.0.0
ENV SINDUK_PORT=58380

RUN mkdir -p /data/.config/sinduk
VOLUME /data

USER sinduk
EXPOSE 58380

CMD ["sinduk", "server", "start", "--host", "0.0.0.0", "--port", "58380"]
