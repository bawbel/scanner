# ── Bawbel Scanner - Dockerfile ───────────────────────────────────────────────
#
# Three targets:
#
#   dev        - local development, all dev tools, editable install
#                docker build --target dev -t bawbel/scanner:dev .
#
#   test       - run the full test suite and exit
#                docker build --target test -t bawbel/scanner:test .
#                docker run --rm bawbel/scanner:test
#
#   production - minimal runtime image, non-root user, read-only fs
#                docker build --target production -t bawbel/scanner:1.2.3 .
#                docker run --rm -v $(pwd)/skills:/scan:ro bawbel/scanner:1.2.3 scan /scan
#
# Build args:
#
#   WITH_YARA=true      include YARA rules engine (default: false)
#   WITH_SEMGREP=true   include Semgrep rules engine (~300MB, default: false)
#   WITH_LLM=true       include LiteLLM semantic engine (default: false)
#   WITH_SANDBOX=true   include sandbox execution engine (default: false)
#   WITH_ALL=true       include all optional engines (default: false)
#
# ─────────────────────────────────────────────────────────────────────────────

ARG PYTHON_VERSION=3.12
ARG VERSION=1.2.3


# ── Base: shared system dependencies ──────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip --quiet


# ── Builder: install Python packages ──────────────────────────────────────────
FROM base AS builder

COPY requirements.txt .

RUN pip install \
        --prefix=/install \
        --no-cache-dir \
        -r requirements.txt


# ── Dev: development environment ──────────────────────────────────────────────
FROM base AS dev

LABEL org.opencontainers.image.title="Bawbel Scanner (dev)" \
      org.opencontainers.image.description="Development environment for bawbel-scanner"

COPY --from=builder /install /usr/local

RUN pip install --no-cache-dir \
        pytest \
        pytest-cov \
        pytest-mock \
        black \
        flake8 \
        flake8-bugbear \
        flake8-simplify \
        flake8-bandit \
        flake8-pyproject \
        bandit \
        pre-commit \
        pip-audit \
        build \
        twine

COPY . /app

RUN pip install -e . --no-deps --quiet

ENV BAWBEL_LOG_LEVEL=DEBUG \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/scan"]

CMD ["/bin/bash"]


# ── Test: run test suite and exit ──────────────────────────────────────────────
FROM dev AS test

LABEL org.opencontainers.image.title="Bawbel Scanner (test)"

RUN python -m pytest tests/ -v --tb=short

CMD ["python", "-m", "pytest", "tests/", "-v", "--tb=short"]


# ── Production: minimal runtime image ─────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS production

ARG VERSION=1.2.3
ARG WITH_YARA=false
ARG WITH_SEMGREP=false
ARG WITH_LLM=false
ARG WITH_SANDBOX=false
ARG WITH_ALL=false

LABEL org.opencontainers.image.title="Bawbel Scanner" \
      org.opencontainers.image.description="Agentic AI security scanner. Detects AVE vulnerabilities. Produces OWASP AIVSS v0.8 scores." \
      org.opencontainers.image.url="https://bawbel.io" \
      org.opencontainers.image.source="https://github.com/bawbel/scanner" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Bawbel" \
      org.opencontainers.image.documentation="https://bawbel.io/docs" \
      bawbel.aivss.spec="0.8" \
      bawbel.ave.records="45"

WORKDIR /app

# Apply all available security patches from Debian security repo
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

COPY scanner/   ./scanner/

RUN pip install --no-cache-dir click rich pydantic --quiet

# Optional engines - install only what is requested
RUN if [ "$WITH_ALL" = "true" ] || [ "$WITH_YARA" = "true" ]; then \
        pip install --no-cache-dir yara-python --quiet; \
    fi

RUN if [ "$WITH_ALL" = "true" ] || [ "$WITH_SEMGREP" = "true" ]; then \
        pip install --no-cache-dir semgrep --quiet; \
    fi

RUN if [ "$WITH_ALL" = "true" ] || [ "$WITH_LLM" = "true" ]; then \
        pip install --no-cache-dir litellm --quiet; \
    fi

RUN if [ "$WITH_ALL" = "true" ] || [ "$WITH_SANDBOX" = "true" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            libseccomp-dev \
        && rm -rf /var/lib/apt/lists/*; \
    fi

RUN useradd \
        --create-home \
        --shell /bin/bash \
        --uid 1000 \
        bawbel \
    && chown -R bawbel:bawbel /app

USER bawbel

VOLUME ["/scan"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from scanner import scan; print('ok')" || exit 1

ENTRYPOINT ["python", "-m", "scanner.cli"]

# Default: show help
# Override in docker run or docker-compose:
#   scan /scan --recursive
#   ssc https://server.example.com
#   conform https://server.example.com
#   pin /scan
#   aibom /scan
CMD ["--help"]
