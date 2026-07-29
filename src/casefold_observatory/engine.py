"""Locale-independent evaluation of ordered Unicode policies."""

from __future__ import annotations

import unicodedata

from casefold_observatory.model import (
    MAX_INPUT_CODEPOINTS,
    MAX_INPUT_UTF8_BYTES,
    MAX_STAGE_CODEPOINTS,
    MAX_STAGE_UTF8_BYTES,
    HazardEvidence,
    HazardHandling,
    HazardKind,
    TransformErrorCode,
    TransformPolicy,
    TransformResult,
    TransformStageEvidence,
    TransformStep,
    _canonical_policy_bytes,
    _create_hazard_evidence,
    _create_result,
    _create_stage_evidence,
    _raise_transform_error,
    _validate_policy,
)

# Unicode's Bidi_Control property is not equivalent to a set of bidi classes:
# ALM, LRM, and RLM have the ordinary AL, L, and R classes. Schema v1 therefore
# enumerates all 12 property members explicitly.
_BIDI_CONTROL_CODEPOINTS = frozenset(
    {
        0x061C,  # ARABIC LETTER MARK
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    }
)


def canonical_policy_bytes(policy: TransformPolicy) -> bytes:
    """Serialize a validated policy to stable, compact ASCII JSON."""

    return _canonical_policy_bytes(policy)


def _hazard_kind(character: str) -> HazardKind | None:
    if ord(character) in _BIDI_CONTROL_CODEPOINTS:
        return HazardKind.BIDI_CONTROL
    category = unicodedata.category(character)
    if category == "Cc":
        return HazardKind.CONTROL
    if category == "Cf":
        return HazardKind.FORMAT
    return None


def _inspect_hazards(identifier: str) -> tuple[HazardEvidence, ...]:
    evidence: list[HazardEvidence] = []
    for index, character in enumerate(identifier):
        kind = _hazard_kind(character)
        if kind is None:
            continue
        evidence.append(
            _create_hazard_evidence(
                codepoint_index=index,
                kind=kind,
                unicode_category=unicodedata.category(character),
                bidi_class=unicodedata.bidirectional(character),
            )
        )
    return tuple(evidence)


def _apply_step(identifier: str, step: TransformStep) -> str:
    if step is TransformStep.NFC:
        return unicodedata.normalize("NFC", identifier)
    if step is TransformStep.NFD:
        return unicodedata.normalize("NFD", identifier)
    if step is TransformStep.NFKC:
        return unicodedata.normalize("NFKC", identifier)
    if step is TransformStep.NFKD:
        return unicodedata.normalize("NFKD", identifier)
    if step is TransformStep.LOWER:
        return identifier.lower()
    if step is TransformStep.UPPER:
        return identifier.upper()
    if step is TransformStep.CASEFOLD:
        return identifier.casefold()
    raise RuntimeError("unsupported transformation step")


def _strict_utf8(identifier: str) -> bytes:
    for codepoint_index, character in enumerate(identifier):
        if 0xD800 <= ord(character) <= 0xDFFF:
            _raise_transform_error(
                TransformErrorCode.INVALID_UNICODE_SCALAR,
                codepoint_index=codepoint_index,
            )
    return identifier.encode("utf-8", errors="strict")


def _enforce_stage_bounds(
    identifier: str,
    *,
    stage_index: int,
) -> bytes:
    if len(identifier) > MAX_STAGE_CODEPOINTS:
        _raise_transform_error(
            TransformErrorCode.STAGE_TOO_LARGE,
            stage_index=stage_index,
        )
    encoded = _strict_utf8(identifier)
    if len(encoded) > MAX_STAGE_UTF8_BYTES:
        _raise_transform_error(
            TransformErrorCode.STAGE_TOO_LARGE,
            stage_index=stage_index,
        )
    return encoded


def _reject_hazards(
    hazards: tuple[HazardEvidence, ...],
    *,
    stage_index: int | None = None,
) -> None:
    if not hazards:
        return
    first = hazards[0]
    _raise_transform_error(
        TransformErrorCode.FORBIDDEN_CODE_POINT,
        codepoint_index=first.codepoint_index,
        stage_index=stage_index,
        hazard_kind=first.kind,
    )


def apply_policy(identifier: str, policy: TransformPolicy) -> TransformResult:
    """Apply one ordered policy and return bounded, non-echoing evidence."""

    if type(identifier) is not str:
        raise TypeError("identifier must be an exact str")
    _validate_policy(policy, require_current_unicode=False)
    if policy.unicode_version != unicodedata.unidata_version:
        _raise_transform_error(TransformErrorCode.POLICY_UNICODE_MISMATCH)
    if identifier == "":
        _raise_transform_error(TransformErrorCode.EMPTY_IDENTIFIER)

    if len(identifier) > MAX_INPUT_CODEPOINTS:
        _raise_transform_error(TransformErrorCode.INPUT_TOO_LARGE)
    encoded_input = _strict_utf8(identifier)
    if len(encoded_input) > MAX_INPUT_UTF8_BYTES:
        _raise_transform_error(TransformErrorCode.INPUT_TOO_LARGE)

    input_hazards = _inspect_hazards(identifier)
    if policy.hazard_handling is HazardHandling.REJECT:
        _reject_hazards(input_hazards)

    transformed = identifier
    stages: list[TransformStageEvidence] = []
    for stage_index, step in enumerate(policy.steps):
        before = transformed
        transformed = _apply_step(before, step)
        _enforce_stage_bounds(transformed, stage_index=stage_index)
        stage_hazards = _inspect_hazards(transformed)
        if policy.hazard_handling is HazardHandling.REJECT:
            _reject_hazards(stage_hazards, stage_index=stage_index)
        stages.append(
            _create_stage_evidence(
                stage_index=stage_index,
                step=step,
                before=before,
                after=transformed,
            )
        )

    output_hazards = _inspect_hazards(transformed)
    return _create_result(
        transformed=transformed,
        policy=policy,
        input_codepoints=len(identifier),
        input_utf8_bytes=len(encoded_input),
        input_hazards=input_hazards,
        output_hazards=output_hazards,
        stages=tuple(stages),
    )
