# Bawbel Sandbox — bundled fallback image
#
# Used when:
#   1. No internet access (air-gapped environments)
#   2. Docker Hub pull fails or rate-limited
#   3. BAWBEL_SANDBOX_IMAGE=local (force local build)
#
# Built automatically by bawbel on first use.
# Rebuild: docker build -t bawbel/sandbox:local <package>/scanner/sandbox/
#
# v0.3.x: text-based behavioural analysis harness
# v1.0:   adds real eBPF syscall tracing

FROM python:3.12-alpine

LABEL org.opencontainers.image.title="Bawbel Sandbox" \
      org.opencontainers.image.description="Bawbel Stage 3 behavioral analysis sandbox" \
      org.opencontainers.image.url="https://bawbel.io" \
      org.opencontainers.image.source="https://github.com/bawbel/bawbel-scanner" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Bawbel"

WORKDIR /sandbox

# Copy harness — stdlib only, no pip installs needed
COPY harness.py /sandbox/harness.py

# Non-root user
RUN adduser -D -u 1000 sandbox
USER sandbox

# /component is mounted read-only at runtime
VOLUME ["/component"]

ENTRYPOINT ["python", "/sandbox/harness.py"]
