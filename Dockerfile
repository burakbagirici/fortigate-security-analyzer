# Multi-use Dockerfile for FortiGate Security Analyzer (CLI & Web UI)
# Base: Official Python 3.11 Slim Linux
FROM python:3.11-slim

LABEL org.opencontainers.image.title="FortiGate Security Analyzer" \
      org.opencontainers.image.description="Static FortiGate configuration review, health audit, and report generator" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="Proprietary"

# Security & python optimization flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root system user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/sh -d /app -M appuser

WORKDIR /app

# Copy project files into container image
COPY pyproject.toml README.md ./
COPY fortigate_analyzer/ ./fortigate_analyzer/
COPY app.py ./
COPY analyzer.py parser.py health_check.py reporting.py runtime_health.py fortios_defaults.py ./
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

# Install package and optional UI dependencies
RUN pip install --no-cache-dir ".[ui]" && \
    chmod +x /app/docker-entrypoint.sh && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER 10001:10001

# Expose port for optional Streamlit UI
EXPOSE 8501

# Entrypoint script supports both CLI and UI ('ui' argument)
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Default action prints CLI help
CMD ["--help"]
