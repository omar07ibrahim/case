"""Validated models for Unicode transformation policies and evidence."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn, Self, final

MAX_INPUT_UTF8_BYTES = 2_048
MAX_INPUT_CODEPOINTS = 1_024
MAX_POLICY_STEPS = 8
MAX_STAGE_UTF8_BYTES = 8_192
MAX_STAGE_CODEPOINTS = 4_096
MAX_UNICODE_VERSION_CHARS = 32

POLICY_SCHEMA = "casefold-observatory.transform-policy"
POLICY_SCHEMA_VERSION = 1


class TransformStep(Enum):
    """One locale-independent operation in an ordered policy."""

    NFC = "normalize:nfc"
    NFD = "normalize:nfd"
    NFKC = "normalize:nfkc"
    NFKD = "normalize:nfkd"
    LOWER = "case:lower"
    UPPER = "case:upper"
    CASEFOLD = "case:casefold"


class HazardHandling(Enum):
    """How a policy treats control and format code points."""

    REJECT = "reject"
    PRESERVE = "preserve"


class HazardKind(Enum):
    """A stable, non-echoing classification of a risky code point."""

    BIDI_CONTROL = "bidi_control"
    CONTROL = "control"
    FORMAT = "format"


class TransformErrorCode(Enum):
    """Stable failure codes that never include the identifier."""

    EMPTY_IDENTIFIER = "empty_identifier"
    FORBIDDEN_CODE_POINT = "forbidden_code_point"
    INPUT_TOO_LARGE = "input_too_large"
    INVALID_UNICODE_SCALAR = "invalid_unicode_scalar"
    POLICY_UNICODE_MISMATCH = "policy_unicode_mismatch"
    STAGE_TOO_LARGE = "stage_too_large"


class IdentifierTransformError(ValueError):
    """A redacted policy-evaluation failure."""

    def __init__(
        self,
        code: TransformErrorCode,
        *,
        codepoint_index: int | None = None,
        stage_index: int | None = None,
        hazard_kind: HazardKind | None = None,
    ) -> None:
        self.code = code
        self.codepoint_index = codepoint_index
        self.stage_index = stage_index
        self.hazard_kind = hazard_kind
        details: list[str] = []
        if codepoint_index is not None:
            details.append(f"codepoint_index={codepoint_index}")
        if stage_index is not None:
            details.append(f"stage_index={stage_index}")
        if hazard_kind is not None:
            details.append(f"hazard={hazard_kind.value}")
        suffix = "" if not details else f" ({', '.join(details)})"
        super().__init__(f"identifier transformation rejected: {code.value}{suffix}")


def _raise_transform_error(
    code: TransformErrorCode,
    *,
    codepoint_index: int | None = None,
    stage_index: int | None = None,
    hazard_kind: HazardKind | None = None,
) -> NoReturn:
    raise IdentifierTransformError(
        code,
        codepoint_index=codepoint_index,
        stage_index=stage_index,
        hazard_kind=hazard_kind,
    )


@final
@dataclass(frozen=True, slots=True, init=False)
class TransformPolicy:
    """An ordered policy bound to one Unicode database version."""

    steps: tuple[TransformStep, ...]
    hazard_handling: HazardHandling
    unicode_version: str

    def __new__(cls) -> Self:
        raise TypeError("TransformPolicy objects are created by create_policy")

    @property
    def policy_id(self) -> str:
        """Return the SHA-256 identity of the canonical policy document."""

        return hashlib.sha256(_canonical_policy_bytes(self)).hexdigest()


@final
@dataclass(frozen=True, slots=True, init=False)
class HazardEvidence:
    """A redacted hazardous-code-point location."""

    codepoint_index: int
    kind: HazardKind
    unicode_category: str
    bidi_class: str

    def __new__(cls) -> Self:
        raise TypeError("HazardEvidence objects are created by apply_policy")


@final
@dataclass(frozen=True, slots=True, init=False)
class TransformStageEvidence:
    """Size and change evidence for one completed policy step."""

    stage_index: int
    step: TransformStep
    changed: bool
    before_codepoints: int
    after_codepoints: int
    before_utf8_bytes: int
    after_utf8_bytes: int

    def __new__(cls) -> Self:
        raise TypeError("TransformStageEvidence objects are created by apply_policy")


@final
@dataclass(frozen=True, slots=True, init=False)
class TransformResult:
    """A transformed identifier plus non-echoing evaluation evidence."""

    transformed: str = field(repr=False)
    policy_id: str
    unicode_version: str
    input_codepoints: int
    input_utf8_bytes: int
    output_codepoints: int
    output_utf8_bytes: int
    input_hazards: tuple[HazardEvidence, ...]
    output_hazards: tuple[HazardEvidence, ...]
    stages: tuple[TransformStageEvidence, ...]

    def __new__(cls) -> Self:
        raise TypeError("TransformResult objects are created by apply_policy")

    @property
    def changed(self) -> bool:
        return any(stage.changed for stage in self.stages)


def create_policy(
    steps: tuple[TransformStep, ...],
    *,
    hazard_handling: HazardHandling = HazardHandling.REJECT,
) -> TransformPolicy:
    """Create a validated policy for the active Unicode database."""

    if type(steps) is not tuple:
        raise TypeError("steps must be an exact tuple")
    if not 1 <= len(steps) <= MAX_POLICY_STEPS:
        raise ValueError(f"steps must contain 1..{MAX_POLICY_STEPS} operations")
    if any(type(step) is not TransformStep for step in steps):
        raise TypeError("every step must be a TransformStep")
    if type(hazard_handling) is not HazardHandling:
        raise TypeError("hazard_handling must be a HazardHandling")

    policy: TransformPolicy = object.__new__(TransformPolicy)
    object.__setattr__(policy, "steps", steps)
    object.__setattr__(policy, "hazard_handling", hazard_handling)
    object.__setattr__(policy, "unicode_version", unicodedata.unidata_version)
    return policy


def _has_canonical_unicode_version_components(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 3 and all(
        part.isascii()
        and part.isdecimal()
        and (part == "0" or not part.startswith("0"))
        for part in parts
    )


def _is_canonical_unicode_version(value: str) -> bool:
    if len(value) > MAX_UNICODE_VERSION_CHARS:
        return False
    return _has_canonical_unicode_version_components(value)


def _validate_policy(
    policy: TransformPolicy,
    *,
    require_current_unicode: bool = True,
) -> None:
    """Recheck policy invariants at every public trust boundary."""

    if type(policy) is not TransformPolicy:
        raise TypeError("policy must be created by create_policy")
    steps = getattr(policy, "steps", None)
    if type(steps) is not tuple or not 1 <= len(steps) <= MAX_POLICY_STEPS:
        raise ValueError("policy contains invalid steps")
    if any(type(step) is not TransformStep for step in steps):
        raise ValueError("policy contains invalid steps")
    if type(getattr(policy, "hazard_handling", None)) is not HazardHandling:
        raise ValueError("policy contains invalid hazard handling")
    unicode_version = getattr(policy, "unicode_version", None)
    if type(unicode_version) is not str or not _is_canonical_unicode_version(
        unicode_version
    ):
        raise ValueError("policy contains an invalid Unicode version")
    if require_current_unicode and unicode_version != unicodedata.unidata_version:
        raise ValueError("policy Unicode version does not match the active runtime")


def _policy_document(policy: TransformPolicy) -> dict[str, object]:
    return {
        "bounds": {
            "max_input_codepoints": MAX_INPUT_CODEPOINTS,
            "max_input_utf8_bytes": MAX_INPUT_UTF8_BYTES,
            "max_policy_steps": MAX_POLICY_STEPS,
            "max_stage_codepoints": MAX_STAGE_CODEPOINTS,
            "max_stage_utf8_bytes": MAX_STAGE_UTF8_BYTES,
            "max_unicode_version_chars": MAX_UNICODE_VERSION_CHARS,
        },
        "hazard_handling": policy.hazard_handling.value,
        "schema": POLICY_SCHEMA,
        "schema_version": POLICY_SCHEMA_VERSION,
        "steps": [step.value for step in policy.steps],
        "unicode_version": policy.unicode_version,
    }


def _canonical_policy_bytes(policy: TransformPolicy) -> bytes:
    _validate_policy(policy)
    return (
        json.dumps(
            _policy_document(policy),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _create_hazard_evidence(
    *,
    codepoint_index: int,
    kind: HazardKind,
    unicode_category: str,
    bidi_class: str,
) -> HazardEvidence:
    evidence: HazardEvidence = object.__new__(HazardEvidence)
    object.__setattr__(evidence, "codepoint_index", codepoint_index)
    object.__setattr__(evidence, "kind", kind)
    object.__setattr__(evidence, "unicode_category", unicode_category)
    object.__setattr__(evidence, "bidi_class", bidi_class)
    return evidence


def _create_stage_evidence(
    *,
    stage_index: int,
    step: TransformStep,
    before: str,
    after: str,
) -> TransformStageEvidence:
    evidence: TransformStageEvidence = object.__new__(TransformStageEvidence)
    object.__setattr__(evidence, "stage_index", stage_index)
    object.__setattr__(evidence, "step", step)
    object.__setattr__(evidence, "changed", before != after)
    object.__setattr__(evidence, "before_codepoints", len(before))
    object.__setattr__(evidence, "after_codepoints", len(after))
    object.__setattr__(evidence, "before_utf8_bytes", len(before.encode("utf-8")))
    object.__setattr__(evidence, "after_utf8_bytes", len(after.encode("utf-8")))
    return evidence


def _create_result(
    *,
    transformed: str,
    policy: TransformPolicy,
    input_codepoints: int,
    input_utf8_bytes: int,
    input_hazards: tuple[HazardEvidence, ...],
    output_hazards: tuple[HazardEvidence, ...],
    stages: tuple[TransformStageEvidence, ...],
) -> TransformResult:
    result: TransformResult = object.__new__(TransformResult)
    object.__setattr__(result, "transformed", transformed)
    object.__setattr__(result, "policy_id", policy.policy_id)
    object.__setattr__(result, "unicode_version", policy.unicode_version)
    object.__setattr__(result, "input_codepoints", input_codepoints)
    object.__setattr__(result, "input_utf8_bytes", input_utf8_bytes)
    object.__setattr__(result, "output_codepoints", len(transformed))
    object.__setattr__(result, "output_utf8_bytes", len(transformed.encode("utf-8")))
    object.__setattr__(result, "input_hazards", input_hazards)
    object.__setattr__(result, "output_hazards", output_hazards)
    object.__setattr__(result, "stages", stages)
    return result
