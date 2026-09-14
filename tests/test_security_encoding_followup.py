import unittest

from deep_tests.security_model import BoundaryViolation, normalize_relative_path, validate_outbound_url


class SecurityEncodingFollowupTests(unittest.TestCase):
    def test_encoded_parent_segment_matrix_fails_closed(self):
        for value in ("message/%2e%2e/secret", "%2E%2e/%2e%2E/secret", "message/%252e%252e/secret", "%2e%2e%2fsecret"):
            with self.assertRaises(BoundaryViolation):
                normalize_relative_path(value)

    def test_embedding_endpoint_authority_confusion_fails_closed(self):
        allowed = {"embeddings.example.test"}
        for value in ("https://embeddings.example.test.attacker.invalid/v1", "https://embeddings.example.test%40attacker.invalid/v1", "https://attacker.invalid/?next=https://embeddings.example.test", "//attacker.invalid/embeddings.example.test"):
            with self.assertRaises(BoundaryViolation):
                validate_outbound_url(value, allowed)


if __name__ == "__main__":
    unittest.main()
