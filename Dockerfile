# ── Bawbel Scanner — Dockerfile ───────────────────────────────────────────────
#
# Three targets:
#
#   dev      — local development, all dev tools, editable install
#              docker build --target dev -t bawbel/scanner:dev .
#
#   test     — run the full test suite and exit
#              docker build --target test -t bawbel/scanner:test .
#              docker run --rm bawbel/scanner:test
#
#   production — minimal runtime image, non-root user, read-only fs
#              docker build --target production -t bawbel/scanner:0.1.0 .
#              docker run --rm -v $(pwd)/skills:/scan:ro bawbel/scanner:0.1.0 scan /scan
#
# ─────────────────────────────────────────────────────────────────────────────

ARG PYTHON_VERSION=3.12


# ── Base: shared system dependencies ─────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS base

WORKDIR /app

# System packages needed across all stages
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        git \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip once here — all stages inherit
RUN pip install --upgrade pip --quiet


# ── Builder: install Python packages ─────────────────────────────────────────
FROM base AS builder

COPY requirements.txt .

RUN pip install \
        --prefix=/install \
        --no-cache-dir \
        -r requirements.txt


# ── Dev: development environment ─────────────────────────────────────────────
FROM base AS dev

LABEL org.opencontainers.image.title="Bawbel Scanner (dev)" \
      org.opencontainers.image.description="Development environment for bawbel-scanner"

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Install dev tools on top
RUN pip install --no-cache-dir \
        pytest \
        pytest-cov \
        pytest-mock \
        black \
        flake8 \
        flake8-bugbear \
        bandit \
        pre-commit \
        pip-audit \
        build \
        twine

# Copy full source — editable so changes reflect immediately
COPY . /app

# Install the package in editable mode so `bawbel` CLI works
RUN pip install -e . --no-deps --quiet

ENV BAWBEL_LOG_LEVEL=DEBUG \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/scan"]

# Default: drop into bash for interactive development
CMD ["/bin/bash"]


# ── Test: run test suite and exit ─────────────────────────────────────────────
FROM dev AS test

LABEL org.opencontainers.image.title="Bawbel Scanner (test)"

# Run tests as part of the build — fails the build if tests fail
# This makes `docker build --target test` a test gate
RUN python -m pytest tests/ -v --tb=short

# In container mode: re-run tests on startup so CI can get the exit code
CMD ["python", "-m", "pytest", "tests/", "-v", "--tb=short"]


# ── Production: minimal runtime image ────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS production

# Optional: build with LLM support
# docker build --target production --build-arg WITH_LLM=true -t bawbel/scanner:0.1.0 .
ARG WITH_LLM=false

LABEL org.opencontainers.image.title="Bawbel Scanner" \
      org.opencontainers.image.description="Agentic AI component security scanner — detects AVE vulnerabilities" \
      org.opencontainers.image.url="https://bawbel.io" \
      org.opencontainers.image.source="https://github.com/bawbel/bawbel-scanner" \
      org.opencontainers.image.version="0.3.0" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Bawbel"

WORKDIR /app

# Copy installed packages from builder — no build tools in production
COPY --from=builder /install /usr/local

# Copy only the packages needed at runtime
# Never copy: tests/, scripts/, docs/, .claude/, .github/
COPY scanner/   ./scanner/
COPY config/    ./config/

# Core runtime deps
RUN pip install --no-cache-dir click rich pydantic --quiet

# Optional LLM support — install litellm if WITH_LLM=true
RUN if [ "$WITH_LLM" = "true" ]; then \
        pip install --no-cache-dir litellm --quiet; \
    fi

# Security: non-root user
RUN useradd \
        --create-home \
        --shell /bin/bash \
        --uid 1000 \
        bawbel \
    && chown -R bawbel:bawbel /app

USER bawbel

# Mount point — always read-only
VOLUME ["/scan"]

# Health check: verify CLI is importable
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from scanner import scan; print('ok')" || exit 1

# Entry point: bawbel CLI via module path (no root cli.py)
ENTRYPOINT ["python", "-m", "scanner.cli"]
CMD ["--help"]
