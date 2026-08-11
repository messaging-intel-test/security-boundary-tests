import unittest

from deep_tests.followup_review import (
    ApprovedBodyLease,
    ConversationFacts,
    FollowUpBoundaryViolation,
    ProposedBodyBinding,
    approve,
    authorize_proposed_body,
    complete_as_sent,
    consume_approved_body,
    revalidate,
    validate_metadata_only,
    validate_proposed_body_request,
)


class FollowUpReviewSecurityTests(unittest.TestCase):
    def eligible(self, **overrides):
        values = {
            "outbound_count": 1,
            "inbound_count": 0,
            "last_direction": "outbound",
            "consent_active": True,
            "suppressed": False,
            "blocked": False,
            "identity_ambiguous": False,
            "conversation_fingerprint": "conv-sha256:fixture-a",
            "rule_revision": "rule-rev-7",
        }
        values.update(overrides)
        return ConversationFacts(**values)

    def confirmations(self):
        return {"matching_evidence", "non_matching_evidence", "conversation_identity", "exact_body"}

    def test_only_exactly_one_outbound_and_zero_inbound_is_eligible(self):
        for facts in (
            self.eligible(outbound_count=0),
            self.eligible(outbound_count=2),
            self.eligible(inbound_count=1),
            self.eligible(last_direction="inbound"),
        ):
            with self.subTest(facts=facts), self.assertRaises(FollowUpBoundaryViolation):
                approve("candidate-1", facts, "synthetic follow-up", self.confirmations())

    def test_suppression_consent_and_identity_ambiguity_fail_closed(self):
        for facts in (
            self.eligible(consent_active=False),
            self.eligible(suppressed=True),
            self.eligible(blocked=True),
            self.eligible(identity_ambiguous=True),
        ):
            with self.subTest(facts=facts), self.assertRaises(FollowUpBoundaryViolation):
                approve("candidate-1", facts, "synthetic follow-up", self.confirmations())

    def test_all_four_review_confirmations_are_required(self):
        for missing in self.confirmations():
            confirmations = self.confirmations() - {missing}
            with self.subTest(missing=missing), self.assertRaises(FollowUpBoundaryViolation):
                approve("candidate-1", self.eligible(), "synthetic follow-up", confirmations)

    def test_revalidation_rejects_changed_thread_rule_body_reply_and_duplicate_claim(self):
        body = "synthetic follow-up"
        facts = self.eligible()
        approval = approve("candidate-1", facts, body, self.confirmations())
        revalidate(approval, facts, body, claim_available=True)

        cases = [
            (self.eligible(conversation_fingerprint="conv-sha256:fixture-b"), body, True),
            (self.eligible(rule_revision="rule-rev-8"), body, True),
            (facts, "edited after approval", True),
            (self.eligible(inbound_count=1, last_direction="inbound"), body, True),
            (facts, body, False),
        ]
        for changed_facts, changed_body, claim_available in cases:
            with self.subTest(changed_facts=changed_facts, changed_body=changed_body, claim=claim_available), self.assertRaises(FollowUpBoundaryViolation):
                revalidate(approval, changed_facts, changed_body, claim_available=claim_available)

    def test_handoff_is_metadata_only_even_when_forbidden_fields_are_nested(self):
        validate_metadata_only({
            "candidate_id": "candidate-1",
            "body_digest": "0" * 64,
            "evidence": {"matching": ["exactly_one_outbound"], "non_matching_count": 239},
        })
        for value in (
            {"message_body": "plaintext"},
            {"transport": {"access-token": "secret"}},
            {"evidence": [{"cookies": "secret"}]},
            {"contact": "synthetic@example.invalid"},
        ):
            with self.subTest(value=value), self.assertRaises(FollowUpBoundaryViolation):
                validate_metadata_only(value)

    def test_approved_body_lease_is_workspace_actor_digest_and_expiry_bound(self):
        lease = ApprovedBodyLease(
            workspace_id="workspace-a",
            candidate_id="candidate-1",
            approval_id="approval-1",
            claim_id="claim-1",
            executor_actor_id="actor-a",
            body_digest="a" * 64,
            expires_at=200,
        )
        denied = [
            {"workspace_id": "workspace-b", "executor_actor_id": "actor-a", "body_digest": "a" * 64, "consent_scope": "crm", "active_consent_count": 1, "now": 100},
            {"workspace_id": "workspace-a", "executor_actor_id": "actor-b", "body_digest": "a" * 64, "consent_scope": "crm", "active_consent_count": 1, "now": 100},
            {"workspace_id": "workspace-a", "executor_actor_id": "actor-a", "body_digest": "b" * 64, "consent_scope": "crm", "active_consent_count": 1, "now": 100},
            {"workspace_id": "workspace-a", "executor_actor_id": "actor-a", "body_digest": "a" * 64, "consent_scope": "message_metadata", "active_consent_count": 1, "now": 100},
            {"workspace_id": "workspace-a", "executor_actor_id": "actor-a", "body_digest": "a" * 64, "consent_scope": "crm", "active_consent_count": 0, "now": 100},
            {"workspace_id": "workspace-a", "executor_actor_id": "actor-a", "body_digest": "a" * 64, "consent_scope": "crm", "active_consent_count": 2, "now": 100},
            {"workspace_id": "workspace-a", "executor_actor_id": "actor-a", "body_digest": "a" * 64, "consent_scope": "crm", "active_consent_count": 1, "now": 200},
            {"workspace_id": "workspace-a", "executor_actor_id": "actor-a", "body_digest": "a" * 64, "consent_scope": "crm", "active_consent_count": 1, "now": 100, "rule_active": False},
            {"workspace_id": "workspace-a", "executor_actor_id": "actor-a", "body_digest": "a" * 64, "consent_scope": "crm", "active_consent_count": 1, "now": 100, "rule_is_current": False},
        ]
        for request in denied:
            with self.subTest(request=request), self.assertRaises(FollowUpBoundaryViolation):
                consume_approved_body(lease, **request)
            self.assertIsNone(lease.consumed_at, "failed checks must not consume the lease")

        consume_approved_body(
            lease,
            workspace_id="workspace-a",
            executor_actor_id="actor-a",
            body_digest="a" * 64,
            consent_scope="crm",
            active_consent_count=1,
            now=101,
        )
        self.assertEqual(lease.consumed_at, 101)
        with self.assertRaises(FollowUpBoundaryViolation):
            consume_approved_body(
                lease,
                workspace_id="workspace-a",
                executor_actor_id="actor-a",
                body_digest="a" * 64,
                consent_scope="crm",
                active_consent_count=1,
                now=102,
            )

    def test_consent_withdrawal_between_review_and_release_fails_closed(self):
        lease = ApprovedBodyLease(
            workspace_id="workspace-a",
            candidate_id="candidate-1",
            approval_id="approval-1",
            claim_id="claim-1",
            executor_actor_id="actor-a",
            body_digest="a" * 64,
            expires_at=200,
        )
        with self.assertRaises(FollowUpBoundaryViolation):
            consume_approved_body(
                lease,
                workspace_id="workspace-a",
                executor_actor_id="actor-a",
                body_digest="a" * 64,
                consent_scope="crm",
                active_consent_count=0,
                now=101,
            )
        self.assertIsNone(lease.consumed_at, "withdrawal race must leave the lease unconsumed")

    def test_proposed_body_is_exact_pending_review_only_and_claim_derived(self):
        binding = ProposedBodyBinding(
            workspace_id="workspace-a",
            candidate_id="candidate-1",
            candidate_version=3,
            rule_revision_id="rule-revision-7",
            conversation_fingerprint="a" * 64,
            expires_at=200,
        )
        request = {
            "candidateVersion": 3,
            "ruleRevisionId": "rule-revision-7",
            "conversationFingerprint": "a" * 64,
        }
        validate_proposed_body_request(request)
        with self.assertRaises(FollowUpBoundaryViolation):
            validate_proposed_body_request({**request, "workspaceId": "workspace-b"})

        valid = {
            "principal_workspace_id": "workspace-a",
            "reviewer_authorized": True,
            "candidate_version": 3,
            "rule_revision_id": "rule-revision-7",
            "conversation_fingerprint": "a" * 64,
            "candidate_status": "pending_review",
            "active_consent_count": 1,
            "suppressed": False,
            "blocked": False,
            "identity_ambiguous": False,
            "rule_active": True,
            "rule_is_current": True,
            "now": 100,
        }
        authorize_proposed_body(binding, **valid)
        denied = [
            {"principal_workspace_id": "workspace-b"},
            {"reviewer_authorized": False},
            {"candidate_version": 4},
            {"rule_revision_id": "rule-revision-8"},
            {"conversation_fingerprint": "b" * 64},
            {"candidate_status": "approved"},
            {"active_consent_count": 0},
            {"suppressed": True},
            {"rule_active": False},
            {"rule_is_current": False},
            {"now": 200},
        ]
        for override in denied:
            with self.subTest(override=override), self.assertRaises(FollowUpBoundaryViolation):
                authorize_proposed_body(binding, **{**valid, **override})

    def test_sent_completion_requires_the_single_use_body_retrieval(self):
        lease = ApprovedBodyLease(
            workspace_id="workspace-a",
            candidate_id="candidate-1",
            approval_id="approval-1",
            claim_id="claim-1",
            executor_actor_id="actor-a",
            body_digest="a" * 64,
            expires_at=200,
        )
        with self.assertRaises(FollowUpBoundaryViolation):
            complete_as_sent(lease)
        consume_approved_body(
            lease,
            workspace_id="workspace-a",
            executor_actor_id="actor-a",
            body_digest="a" * 64,
            consent_scope="crm",
            active_consent_count=1,
            now=101,
        )
        complete_as_sent(lease)


if __name__ == "__main__":
    unittest.main()
