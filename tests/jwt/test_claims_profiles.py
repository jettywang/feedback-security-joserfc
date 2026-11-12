from unittest import TestCase

from joserfc import jwt
from joserfc.errors import (
    ExpiredTokenError,
    InvalidClaimError,
    MissingClaimError,
)
from joserfc.jwk import OctKey

NOW = 1765000000

#: finance notifications require extra tracking claims on top of the
#: standard registered claims
FINANCE_CLAIMS = {
    "iss": "https://notify.example.com",
    "sub": "finance-notification",
    "exp": NOW + 600,
    "iat": NOW,
    "trace_id": "trc-2026-0001",
    "settlement_ref": "stl-8899",
}

#: ops notifications only require the standard registered claims
OPS_CLAIMS = {
    "iss": "https://notify.example.com",
    "sub": "ops-notification",
    "exp": NOW + 600,
    "iat": NOW,
}


def make_profiles() -> jwt.ClaimsProfileRegistry:
    return jwt.ClaimsProfileRegistry(
        finance=jwt.JWTClaimsRegistry(
            now=NOW,
            iss={"essential": True, "value": "https://notify.example.com"},
            sub={"essential": True},
            exp={"essential": True},
            trace_id={"essential": True},
            settlement_ref={"essential": True},
        ),
        ops=jwt.JWTClaimsRegistry(
            now=NOW,
            iss={"essential": True, "value": "https://notify.example.com"},
            sub={"essential": True},
            exp={"essential": True},
        ),
    )


class TestClaimsProfileRegistry(TestCase):
    def setUp(self):
        self.key = OctKey.import_key("secret")
        self.profiles = make_profiles()

    def decode(self, claims):
        text = jwt.encode({"alg": "HS256"}, claims, self.key)
        return jwt.decode(text, self.key)

    def test_finance_valid_sample(self):
        token = self.decode(FINANCE_CLAIMS)
        self.profiles.validate("finance", token.claims)

    def test_finance_missing_field_sample(self):
        claims = {k: v for k, v in FINANCE_CLAIMS.items() if k != "trace_id"}
        token = self.decode(claims)
        with self.assertRaises(MissingClaimError) as cm:
            self.profiles.validate("finance", token.claims)
        error = cm.exception
        # the error names the missing field and the selected profile
        self.assertEqual(error.claim, "trace_id")
        self.assertIn("trace_id", error.description)
        self.assertIn("finance", error.description)
        # the error must not leak the claims payload
        self.assertNotIn("stl-8899", str(error))
        self.assertNotIn("finance-notification", str(error))

    def test_ops_valid_sample(self):
        token = self.decode(OPS_CLAIMS)
        self.profiles.validate("ops", token.claims)

    def test_ops_missing_field_sample(self):
        claims = {k: v for k, v in OPS_CLAIMS.items() if k != "sub"}
        token = self.decode(claims)
        with self.assertRaises(MissingClaimError) as cm:
            self.profiles.validate("ops", token.claims)
        error = cm.exception
        self.assertEqual(error.claim, "sub")
        self.assertIn("sub", error.description)
        self.assertIn("ops", error.description)
        self.assertNotIn("https://notify.example.com", str(error))

    def test_ops_accepts_extra_tracking_claims(self):
        # the ops profile does not reject finance-style claims
        token = self.decode(FINANCE_CLAIMS)
        self.profiles.validate("ops", token.claims)

    def test_finance_rejects_ops_sample(self):
        # ops notifications lack the tracking claims finance requires
        token = self.decode(OPS_CLAIMS)
        with self.assertRaises(MissingClaimError) as cm:
            self.profiles.validate("finance", token.claims)
        self.assertEqual(cm.exception.claim, "settlement_ref,trace_id")
        self.assertIn("finance", cm.exception.description)

    def test_time_validation_is_reused(self):
        claims = {**OPS_CLAIMS, "exp": NOW - 1}
        token = self.decode(claims)
        with self.assertRaises(ExpiredTokenError) as cm:
            self.profiles.validate("ops", token.claims)
        self.assertEqual(cm.exception.claim, "exp")
        self.assertIn("ops", cm.exception.description)

    def test_invalid_claim_keeps_error_class(self):
        claims = {**OPS_CLAIMS, "iss": "https://evil.example.com"}
        token = self.decode(claims)
        with self.assertRaises(InvalidClaimError) as cm:
            self.profiles.validate("ops", token.claims)
        self.assertEqual(cm.exception.claim, "iss")
        self.assertIn("ops", cm.exception.description)

    def test_unknown_profile(self):
        token = self.decode(OPS_CLAIMS)
        self.assertRaises(ValueError, self.profiles.validate, "unknown", token.claims)

    def test_requires_at_least_one_profile(self):
        self.assertRaises(ValueError, jwt.ClaimsProfileRegistry)
