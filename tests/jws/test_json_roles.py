from unittest import TestCase, mock

from joserfc._rfc7515.json import verify_general_json
from joserfc.errors import VerificationBudgetExceededError
from joserfc.jwk import KeySet, guess_key
from joserfc.jws import (
    HeaderDict,
    JWSRegistry,
    VerificationBudget,
    extract_general_json,
    serialize_json,
    verify_json_roles,
)
from tests.base import load_key


class TestVerifyJsonRoles(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice_key = load_key("ec-p256-alice.json", {"kid": "alice"})
        cls.bob_key = load_key("ec-p256-bob.json", {"kid": "bob"})
        cls.role_keys = {"manager": cls.alice_key, "auditor": cls.bob_key}

    def sign_message(self, kids: list[str]):
        # sign every member with the key of the given kid
        keys = KeySet([self.alice_key, self.bob_key])
        members: list[HeaderDict] = [
            {"protected": {"alg": "ES256"}, "header": {"kid": kid}} for kid in kids
        ]
        return serialize_json(members, b"approve-request-42", keys)

    def count_verify_calls(self, registry: JWSRegistry):
        alg = registry.get_alg("ES256")
        return mock.patch.object(alg, "verify", wraps=alg.verify)

    def test_two_distinct_roles_approved(self):
        message = self.sign_message(["alice", "bob"])
        registry = JWSRegistry(algorithms=["ES256"])
        with self.count_verify_calls(registry) as verify_spy:
            result = verify_json_roles(message, self.role_keys, registry=registry)
        self.assertTrue(result.approved)
        self.assertEqual(result.roles, {"manager": True, "auditor": True})
        self.assertFalse(result.budget_exhausted)
        self.assertEqual(result.verifications, 2)
        self.assertEqual(verify_spy.call_count, 2)

    def test_duplicated_role_cannot_cover_other_role(self):
        message = self.sign_message(["alice", "alice"])
        registry = JWSRegistry(algorithms=["ES256"])
        with self.count_verify_calls(registry) as verify_spy:
            result = verify_json_roles(message, self.role_keys, registry=registry)
        self.assertFalse(result.approved)
        self.assertEqual(result.roles, {"manager": True, "auditor": False})
        self.assertFalse(result.budget_exhausted)
        # the second alice signature is not a candidate for bob's key
        self.assertEqual(result.verifications, 1)
        self.assertEqual(verify_spy.call_count, 1)

    def test_budget_exhaustion_is_reported(self):
        message = self.sign_message(["alice", "bob"])
        registry = JWSRegistry(algorithms=["ES256"])
        with self.count_verify_calls(registry) as verify_spy:
            result = verify_json_roles(message, self.role_keys, registry=registry, max_verifications=1)
        self.assertFalse(result.approved)
        self.assertEqual(result.roles, {"manager": True, "auditor": False})
        self.assertTrue(result.budget_exhausted)
        self.assertEqual(result.verifications, 1)
        self.assertEqual(verify_spy.call_count, 1)

    def test_budget_allows_all_roles(self):
        message = self.sign_message(["alice", "bob"])
        registry = JWSRegistry(algorithms=["ES256"])
        with self.count_verify_calls(registry) as verify_spy:
            result = verify_json_roles(message, self.role_keys, registry=registry, max_verifications=2)
        self.assertTrue(result.approved)
        self.assertFalse(result.budget_exhausted)
        self.assertEqual(result.verifications, 2)
        self.assertEqual(verify_spy.call_count, 2)

    def test_zero_budget_verifies_nothing(self):
        message = self.sign_message(["alice", "bob"])
        registry = JWSRegistry(algorithms=["ES256"])
        with self.count_verify_calls(registry) as verify_spy:
            result = verify_json_roles(message, self.role_keys, registry=registry, max_verifications=0)
        self.assertFalse(result.approved)
        self.assertEqual(result.roles, {"manager": False, "auditor": False})
        self.assertTrue(result.budget_exhausted)
        self.assertEqual(result.verifications, 0)
        self.assertEqual(verify_spy.call_count, 0)

    def test_required_roles_subset(self):
        message = self.sign_message(["alice", "bob"])
        result = verify_json_roles(message, self.role_keys, required_roles=["auditor"])
        self.assertTrue(result.approved)
        self.assertEqual(result.roles, {"auditor": True})
        self.assertEqual(result.verifications, 1)

    def test_missing_role_keys(self):
        message = self.sign_message(["alice"])
        with self.assertRaises(ValueError):
            verify_json_roles(message, {"manager": self.alice_key}, required_roles=["manager", "auditor"])

    def test_failed_verification_consumes_budget(self):
        message = self.sign_message(["alice", "bob"])
        # tamper with bob's signature
        message["signatures"][1]["signature"] = message["signatures"][0]["signature"]
        registry = JWSRegistry(algorithms=["ES256"])
        with self.count_verify_calls(registry) as verify_spy:
            result = verify_json_roles(message, self.role_keys, registry=registry)
        self.assertFalse(result.approved)
        self.assertEqual(result.roles, {"manager": True, "auditor": False})
        self.assertEqual(result.verifications, 2)
        self.assertEqual(verify_spy.call_count, 2)


class TestVerificationBudget(TestCase):
    key = None

    @classmethod
    def setUpClass(cls):
        cls.key = load_key("ec-p256-alice.json", {"kid": "alice"})

    def setUp(self):
        self.registry = JWSRegistry(algorithms=["ES256"])
        member: HeaderDict = {"protected": {"alg": "ES256"}, "header": {"kid": "alice"}}
        self.message = serialize_json([member, member], b"hello", self.key)

    def find_key(self, member):
        return guess_key(self.key, member, use="sig")

    def test_budget_counts_verify_operations(self):
        obj = extract_general_json(self.message, self.registry)
        budget = VerificationBudget()
        self.assertTrue(verify_general_json(obj, self.registry, self.find_key, budget))
        self.assertEqual(budget.used, 2)
        self.assertFalse(budget.exhausted)

    def test_exhausted_budget_raises(self):
        obj = extract_general_json(self.message, self.registry)
        budget = VerificationBudget(1)
        with self.assertRaises(VerificationBudgetExceededError):
            verify_general_json(obj, self.registry, self.find_key, budget)
        self.assertEqual(budget.used, 1)
        self.assertTrue(budget.exhausted)

    def test_negative_budget_rejected(self):
        with self.assertRaises(ValueError):
            VerificationBudget(-1)
