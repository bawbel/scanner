"""
Bawbel Scanner - which engines ran, and which could not.

A scan that ran one engine of six prints the same result as one that ran all six, unless
the result says so (issue #124). EngineDegradation is one engine that did not run, and why.
"""

from dataclasses import dataclass
from typing import Optional

# Every detection engine, in the order scan() runs them.
ENGINES: tuple[str, ...] = ("pattern", "yara", "semgrep", "llm", "magika", "sandbox")


class DegradedReason:
    """Why an engine did not run. Values appear in JSON and SARIF output: never rename."""

    NOT_INSTALLED = "not_installed"  # optional dependency, CLI tool, or image is missing
    NO_API_KEY = "no_api_key"  # LLM engine: no provider key and no model configured
    TIMEOUT = "timeout"  # the engine started and did not finish in time
    API_ERROR = "api_error"  # LLM engine: the provider call failed or returned nothing usable
    DOCKER_UNAVAILABLE = "docker_unavailable"  # sandbox: Docker is not running
    DISABLED_BY_CONFIG = "disabled_by_config"  # turned off by an environment variable or default
    RULES_MISSING = "rules_missing"  # the engine's rule file is not there
    ENGINE_ERROR = "engine_error"  # the engine started and failed
    SKIPPED_CONTENT_TYPE = "skipped_content_type"  # Magika found a dangerous type; text skipped


@dataclass(frozen=True)
class EngineDegradation:
    """One engine that did not run on a scan."""

    engine: str  # one of ENGINES
    reason: str  # one of DegradedReason
    detail: Optional[str] = None  # an error CODE such as "E013"; never exception text

    def to_dict(self) -> dict:
        return {"engine": self.engine, "reason": self.reason, "detail": self.detail}
