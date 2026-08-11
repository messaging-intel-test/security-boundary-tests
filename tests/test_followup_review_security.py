import unittest

from deep_tests.followup_review import (
    ConversationFacts,
    FollowUpBoundaryViolation,
    approve,
    revalidate,
    validate_metadata_only,
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


if __name__ == "__main__":
    unittest.main()
