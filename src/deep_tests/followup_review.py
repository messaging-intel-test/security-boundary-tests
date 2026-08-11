from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping


class FollowUpBoundaryViolation(ValueError):
    pass


_PLAINTEXT_KEYS = {
    "body",
    "message",
    "message_body",
    "contact",
    "contact_value",
    "cookie",
    "cookies",
    "token",
    "access_token",
    "refresh_token",
    "provider_session",
}


@dataclass(frozen=True)
class ConversationFacts:
    outbound_count: int
    inbound_count: int
    last_direction: str
    consent_active: bool
    suppressed: bool
    blocked: bool
    identity_ambiguous: bool
    conversation_fingerprint: str
    rule_revision: str


@dataclass(frozen=True)
class Approval:
    candidate_id: str
    conversation_fingerprint: str
    rule_revision: str
    body_digest: str
    confirmations: frozenset[str]


@dataclass
class ApprovedBodyLease:
    workspace_id: str
    candidate_id: str
    approval_id: str
    claim_id: str
    executor_actor_id: str
    body_digest: str
    expires_at: int
    consumed_at: int | None = None


@dataclass(frozen=True)
class ProposedBodyBinding:
    workspace_id: str
    candidate_id: str
    candidate_version: int
    rule_revision_id: str
    conversation_fingerprint: str
    expires_at: int


_REQUIRED_CONFIRMATIONS = frozenset(
    {"matching_evidence", "non_matching_evidence", "conversation_identity", "exact_body"}
)


def _digest_body(body: str) -> str:
    normalized = body.replace("\r\n", "\n")
    if not normalized.strip():
        raise FollowUpBoundaryViolation("empty follow-up body")
    return sha256(normalized.encode("utf-8")).hexdigest()


def validate_candidate(facts: ConversationFacts) -> None:
    if facts.outbound_count != 1:
        raise FollowUpBoundaryViolation("candidate requires exactly one outbound message")
    if facts.inbound_count != 0:
        raise FollowUpBoundaryViolation("candidate is disqualified by an inbound reply")
    if facts.last_direction != "outbound":
        raise FollowUpBoundaryViolation("last message must be outbound")
    if not facts.consent_active or facts.suppressed or facts.blocked:
        raise FollowUpBoundaryViolation("consent or suppression boundary blocks candidate")
    if facts.identity_ambiguous:
        raise FollowUpBoundaryViolation("conversation identity is ambiguous")
    if not facts.conversation_fingerprint or not facts.rule_revision:
        raise FollowUpBoundaryViolation("candidate lacks immutable review identity")


def approve(candidate_id: str, facts: ConversationFacts, body: str, confirmations: set[str]) -> Approval:
    validate_candidate(facts)
    frozen = frozenset(confirmations)
    if frozen != _REQUIRED_CONFIRMATIONS:
        raise FollowUpBoundaryViolation("all four review confirmations are required exactly")
    return Approval(
        candidate_id=candidate_id,
        conversation_fingerprint=facts.conversation_fingerprint,
        rule_revision=facts.rule_revision,
        body_digest=_digest_body(body),
        confirmations=frozen,
    )


def revalidate(approval: Approval, facts: ConversationFacts, body: str, *, claim_available: bool) -> None:
    validate_candidate(facts)
    if approval.conversation_fingerprint != facts.conversation_fingerprint:
        raise FollowUpBoundaryViolation("conversation fingerprint changed")
    if approval.rule_revision != facts.rule_revision:
        raise FollowUpBoundaryViolation("rule revision changed")
    if approval.body_digest != _digest_body(body):
        raise FollowUpBoundaryViolation("approved body changed")
    if not claim_available:
        raise FollowUpBoundaryViolation("idempotency claim already consumed")


def consume_approved_body(
    lease: ApprovedBodyLease,
    *,
    workspace_id: str,
    executor_actor_id: str,
    body_digest: str,
    consent_scope: str,
    active_consent_count: int,
    now: int,
    rule_active: bool = True,
    rule_is_current: bool = True,
) -> None:
    if workspace_id != lease.workspace_id:
        raise FollowUpBoundaryViolation("body lease workspace mismatch")
    if executor_actor_id != lease.executor_actor_id:
        raise FollowUpBoundaryViolation("body lease actor mismatch")
    if now >= lease.expires_at:
        raise FollowUpBoundaryViolation("body lease expired")
    if body_digest != lease.body_digest:
        raise FollowUpBoundaryViolation("approved body digest mismatch")
    if consent_scope != "crm" or active_consent_count != 1:
        raise FollowUpBoundaryViolation("exactly one current CRM consent is required")
    if not rule_active or not rule_is_current:
        raise FollowUpBoundaryViolation("approved body rule is paused or superseded")
    if lease.consumed_at is not None:
        raise FollowUpBoundaryViolation("approved body lease already consumed")
    lease.consumed_at = now


def authorize_proposed_body(
    binding: ProposedBodyBinding,
    *,
    principal_workspace_id: str,
    reviewer_authorized: bool,
    candidate_version: int,
    rule_revision_id: str,
    conversation_fingerprint: str,
    candidate_status: str,
    active_consent_count: int,
    suppressed: bool,
    blocked: bool,
    identity_ambiguous: bool,
    rule_active: bool,
    rule_is_current: bool,
    now: int,
) -> None:
    if principal_workspace_id != binding.workspace_id or not reviewer_authorized:
        raise FollowUpBoundaryViolation("proposed body reviewer is unauthorized")
    if candidate_status != "pending_review" or now >= binding.expires_at:
        raise FollowUpBoundaryViolation("proposed body candidate is not pending and current")
    if (
        candidate_version != binding.candidate_version
        or rule_revision_id != binding.rule_revision_id
        or conversation_fingerprint != binding.conversation_fingerprint
    ):
        raise FollowUpBoundaryViolation("proposed body request binding is stale")
    if active_consent_count != 1 or suppressed or blocked or identity_ambiguous:
        raise FollowUpBoundaryViolation("current consent or suppression boundary blocks review")
    if not rule_active or not rule_is_current:
        raise FollowUpBoundaryViolation("proposed body rule is paused or superseded")


def validate_proposed_body_request(mapping: Mapping[str, object]) -> None:
    if set(mapping) != {"candidateVersion", "ruleRevisionId", "conversationFingerprint"}:
        raise FollowUpBoundaryViolation("proposed body request shape is not exact")
    version = mapping["candidateVersion"]
    fingerprint = mapping["conversationFingerprint"]
    if not isinstance(version, int) or isinstance(version, bool) or not 1 <= version <= 2_147_483_647:
        raise FollowUpBoundaryViolation("candidate version is outside the PostgreSQL bound")
    if not isinstance(mapping["ruleRevisionId"], str) or not mapping["ruleRevisionId"]:
        raise FollowUpBoundaryViolation("rule revision id is missing")
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(character not in "0123456789abcdef" for character in fingerprint)
    ):
        raise FollowUpBoundaryViolation("conversation fingerprint is not lowercase SHA-256")


def complete_as_sent(lease: ApprovedBodyLease) -> None:
    if lease.consumed_at is None:
        raise FollowUpBoundaryViolation("sent completion requires approved body retrieval")


def validate_metadata_only(mapping: Mapping[str, object]) -> None:
    stack: list[tuple[str, object]] = list(mapping.items())
    while stack:
        key, value = stack.pop()
        normalized = key.lower().replace("-", "_")
        if normalized in _PLAINTEXT_KEYS:
            raise FollowUpBoundaryViolation(f"forbidden plaintext field: {key}")
        if isinstance(value, Mapping):
            stack.extend((str(child_key), child_value) for child_key, child_value in value.items())
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, Mapping):
                    stack.extend((str(child_key), child_value) for child_key, child_value in item.items())
