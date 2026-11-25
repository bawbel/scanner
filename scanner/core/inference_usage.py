"""
Bawbel Scanner - read what an LLM call reported about itself.

Stage 2 and FP-4 call an LLM through LiteLLM. After each call, record_inference() reads the
response, builds an InferenceUsage, and files it with the ledger of the scan in progress
(issue #150).

The rule: NEVER estimate. A call whose provider reported no token counts has no entry, and a
count that is not a plain non-negative integer is not a count. A wrong cost number is worse than
none, so there is no cost field either.

Four things are read from a response: the usage block's prompt and completion counts, the model
name, and LiteLLM's own record of the provider. The latency is measured by the caller. The prompt,
the completion text, the API key, and the file content are never touched here.

Nothing in this module can raise into an engine.
"""

from typing import Any, Optional

from scanner.core.engine_ledger import report_inference
from scanner.messages import Logs
from scanner.models.inference_usage import (
    MODEL_FROM_REQUEST,
    MODEL_FROM_RESPONSE,
    USAGE_FROM_PROVIDER,
    InferenceUsage,
)
from scanner.utils import get_logger

log = get_logger(__name__)


def _field(obj: Any, name: str) -> Any:
    """An attribute of a response object, or a key of a plain dict. None when it is absent."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _count(value: Any) -> Optional[int]:
    """A reported token count, or None. A bool, a float, text or a negative is not a count."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _text(value: Any) -> Optional[str]:
    """A non-empty string, stripped, or None."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _provider(litellm_module: Any, response: Any, model: str) -> Optional[str]:
    """The provider as LiteLLM resolves it, or None. Never guessed from the model name here."""
    hidden = _field(response, "_hidden_params")
    if isinstance(hidden, dict):
        found = _text(hidden.get("custom_llm_provider"))
        if found:
            return found
    try:
        return _text(litellm_module.get_llm_provider(model)[1])
    except Exception:  # nosec B110  # noqa: S110 - an unknown provider is None, not an error
        return None


def usage_from_response(
    litellm_module: Any, response: Any, request_model: str, latency_ms: int
) -> Optional[InferenceUsage]:
    """
    The usage the provider reported for one call, or None if it reported none.

    None when the response has no usage block, or when either token count is missing or is not a
    non-negative integer. A partial entry would invite a sum that is wrong, so there is none.
    """
    usage = _field(response, "usage")
    if usage is None:
        return None
    prompt_tokens = _count(_field(usage, "prompt_tokens"))
    completion_tokens = _count(_field(usage, "completion_tokens"))
    if prompt_tokens is None or completion_tokens is None:
        return None

    reported_model = _text(_field(response, "model"))
    model = reported_model or _text(request_model)
    if model is None:
        return None

    return InferenceUsage(
        provider=_provider(litellm_module, response, request_model),
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        latency_ms=max(0, int(latency_ms)),
        model_source=MODEL_FROM_RESPONSE if reported_model else MODEL_FROM_REQUEST,
        usage_source=USAGE_FROM_PROVIDER,
    )


def record_inference(
    litellm_module: Any, response: Any, request_model: str, latency_ms: int
) -> None:
    """Record the usage of one LLM call on the scan in progress. Never raises."""
    try:
        usage = usage_from_response(litellm_module, response, request_model, latency_ms)
        if usage is None:
            log.debug(Logs.INFERENCE_NOT_REPORTED, request_model)
            return
        report_inference(usage)
    except Exception as e:  # nosec B110  # noqa: S110 - the engines must never raise
        log.debug(Logs.INFERENCE_NOT_RECORDED, request_model, type(e).__name__)
