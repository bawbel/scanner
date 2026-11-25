"""
Bawbel Scanner - what one LLM call reported about itself.

Stage 2 and FP-4 call an LLM. One InferenceUsage is one such call whose provider reported token
counts (issue #150). There is no cost field: a cost is a price table applied to token counts, and
a scanner that estimates one would print a number nobody measured.

An InferenceUsage never holds an API key, prompt text, or file content. It holds the seven
fields below and nothing else.
"""

from dataclasses import dataclass
from typing import Optional

# Where the model name came from.
MODEL_FROM_RESPONSE = "response"  # the provider's response named the model
MODEL_FROM_REQUEST = "request"  # the response did not, so this is the model that was asked for

# Where the token counts came from. The scanner never estimates them, so there is one value.
USAGE_FROM_PROVIDER = "provider_response"


@dataclass(frozen=True)
class InferenceUsage:
    """One LLM call, as the provider reported it. Values appear in JSON: never rename."""

    provider: Optional[str]  # as LiteLLM resolves it, or None when it could not be resolved
    model: str
    prompt_tokens: int  # as the provider reported them
    completion_tokens: int  # as the provider reported them
    latency_ms: int  # measured by the scanner around the call
    model_source: str  # MODEL_FROM_RESPONSE or MODEL_FROM_REQUEST
    usage_source: str  # USAGE_FROM_PROVIDER

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "latency_ms": self.latency_ms,
            "model_source": self.model_source,
            "usage_source": self.usage_source,
        }
