"""Explicit, bounded Unicode identifier transformation policies."""

from casefold_observatory.engine import apply_policy, canonical_policy_bytes
from casefold_observatory.model import (
    MAX_INPUT_CODEPOINTS,
    MAX_INPUT_UTF8_BYTES,
    MAX_POLICY_STEPS,
    MAX_STAGE_CODEPOINTS,
    MAX_STAGE_UTF8_BYTES,
    MAX_UNICODE_VERSION_CHARS,
    HazardEvidence,
    HazardHandling,
    HazardKind,
    IdentifierTransformError,
    TransformErrorCode,
    TransformPolicy,
    TransformResult,
    TransformStageEvidence,
    TransformStep,
    create_policy,
)

__all__ = [
    "MAX_INPUT_CODEPOINTS",
    "MAX_INPUT_UTF8_BYTES",
    "MAX_POLICY_STEPS",
    "MAX_STAGE_CODEPOINTS",
    "MAX_STAGE_UTF8_BYTES",
    "MAX_UNICODE_VERSION_CHARS",
    "HazardEvidence",
    "HazardHandling",
    "HazardKind",
    "IdentifierTransformError",
    "TransformErrorCode",
    "TransformPolicy",
    "TransformResult",
    "TransformStageEvidence",
    "TransformStep",
    "apply_policy",
    "canonical_policy_bytes",
    "create_policy",
]
