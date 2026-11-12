from unittest import TestCase

from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import (
    ECKey,
    KeySet,
    OKPKey,
    OctKey,
    RSAKey,
    ThumbprintDirectory,
    is_thumbprint_uri,
    normalize_thumbprint_identifier,
    parse_thumbprint_uri,
)
from tests.keys import read_key

# local sample key pairs, one per supported asymmetric key type
SAMPLE_PAIRS = [
    (RSAKey, "RFC7520-RSA-private.json", "RFC7520-RSA-public.json"),
    (ECKey, "RFC7520-EC-private.json", "RFC7520-EC-public.json"),
    (OKPKey, "okp-ed25519-private.json", "okp-ed25519-public.json"),
]


class TestThumbprintURIHelpers(TestCase):
    def test_is_thumbprint_uri(self):
        uri = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"
        self.assertTrue(is_thumbprint_uri(uri))
        self.assertTrue(is_thumbprint_uri(uri.replace("sha-256", "sha-512")))
        self.assertFalse(is_thumbprint_uri("9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"))
        self.assertFalse(is_thumbprint_uri("urn:ietf:params:oauth:jwk-thumbprint:sha-1:abc"))
        self.assertFalse(is_thumbprint_uri("not-a-uri"))

    def test_parse_thumbprint_uri(self):
        parsed = parse_thumbprint_uri(
            "urn:ietf:params:oauth:jwk-thumbprint:sha-384:dHri3SADZkrush5HU_50AoRhcKFryN-PI6jPBtPL55M"
        )
        self.assertEqual(parsed.digest_method, "sha384")
        self.assertEqual(parsed.thumbprint, "dHri3SADZkrush5HU_50AoRhcKFryN-PI6jPBtPL55M")

    def test_parse_invalid_uri(self):
        self.assertRaises(ValueError, parse_thumbprint_uri, "bare-thumbprint")
        self.assertRaises(ValueError, parse_thumbprint_uri, "urn:ietf:params:oauth:jwk-thumbprint:sha-256:")

    def test_normalize_identifier(self):
        bare = "9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"
        uri = f"urn:ietf:params:oauth:jwk-thumbprint:sha-256:{bare}"
        self.assertEqual(normalize_thumbprint_identifier(bare), bare)
        self.assertEqual(normalize_thumbprint_identifier(uri), bare)


class TestThumbprintDirectory(TestCase):
    def _pair(self, index):
        cls, private_file, public_file = SAMPLE_PAIRS[index]
        return cls, cls.import_key(read_key(private_file)), cls.import_key(read_key(public_file))

    def test_public_private_material_maps_to_same_entry(self):
        for index in range(len(SAMPLE_PAIRS)):
            cls, private_key, public_key = self._pair(index)
            with self.subTest(kty=cls.key_type):
                directory = ThumbprintDirectory([private_key])
                # the public JWK carries no private fields but the same canonical material
                self.assertEqual(private_key.thumbprint(), public_key.thumbprint())
                self.assertEqual(private_key.thumbprint_uri(), public_key.thumbprint_uri())

                # resolving through the new URI index returns the registered private key
                self.assertIs(directory.get(public_key.thumbprint_uri()), private_key)
                # resolving through the legacy bare thumbprint still works
                self.assertIs(directory.get(public_key.thumbprint()), private_key)
                # the pre-existing kid keeps selecting the key for legacy callers
                self.assertIs(directory.get_by_kid(public_key.kid), private_key)

    def test_three_indexes_resolve_one_key(self):
        _, private_key, _ = self._pair(0)
        directory = ThumbprintDirectory([private_key])
        index = directory.index_of(private_key)

        self.assertEqual(index.thumbprint, private_key.thumbprint())
        self.assertEqual(index.thumbprint_uri, private_key.thumbprint_uri())
        self.assertTrue(index.thumbprint_uri.endswith(index.thumbprint))
        self.assertEqual(index.kid, private_key.kid)

        self.assertIs(directory.get_by_thumbprint(index.thumbprint), private_key)
        self.assertIs(directory.get_by_thumbprint_uri(index.thumbprint_uri), private_key)
        self.assertIs(directory.get_by_kid(index.kid), private_key)
        # the generic resolver accepts every representation
        self.assertIs(directory.get(index.thumbprint), private_key)
        self.assertIs(directory.get(index.thumbprint_uri), private_key)
        self.assertIs(directory.get(index.kid), private_key)

    def test_legacy_kid_is_preserved_unchanged(self):
        _, private_key, _ = self._pair(1)
        original_kid = private_key.kid
        directory = ThumbprintDirectory([private_key])
        directory.add_key(private_key)
        # registering must never overwrite the JWK's own kid with a thumbprint
        self.assertEqual(private_key.kid, original_kid)
        self.assertEqual(directory.index_of(private_key).kid, original_kid)

    def test_auto_kid_falls_back_to_bare_thumbprint(self):
        key = OctKey.import_key("secret-value")
        self.assertIsNone(key.kid)
        directory = ThumbprintDirectory([key])
        # ensure_kid fills the kid with the bare RFC 7638 thumbprint, not the URI
        self.assertEqual(key.kid, key.thumbprint())
        self.assertEqual(directory.index_of(key).kid, key.thumbprint())
        self.assertIn(key.thumbprint(), directory)
        self.assertIn(key.thumbprint_uri(), directory)

    def test_contains_and_length(self):
        key = OctKey.import_key("secret-value")
        directory = ThumbprintDirectory([key])
        self.assertEqual(len(directory), 1)
        self.assertIn(key.thumbprint(), directory)
        self.assertIn(key.thumbprint_uri(), directory)
        self.assertNotIn("missing", directory)
        self.assertNotIn(123, directory)

    def test_missing_identifier_raises(self):
        directory = ThumbprintDirectory([OctKey.import_key("secret-value")])
        self.assertRaises(InvalidKeyIdError, directory.get, "unknown")
        self.assertRaises(InvalidKeyIdError, directory.get_by_kid, "unknown")
        self.assertRaises(InvalidKeyIdError, directory.get_by_thumbprint, "unknown")
        self.assertRaises(
            InvalidKeyIdError,
            directory.get_by_thumbprint_uri,
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:unknown",
        )

    def test_single_key_allows_none_identifier(self):
        key = OctKey.import_key("secret-value")
        directory = ThumbprintDirectory([key])
        self.assertIs(directory.get(None), key)
        self.assertIs(directory.get_by_kid(None), key)

    def test_none_identifier_requires_single_key(self):
        directory = ThumbprintDirectory([
            OctKey.import_key("one"),
            OctKey.import_key("two"),
        ])
        self.assertRaises(InvalidKeyIdError, directory.get, None)

    def test_re_adding_same_material_is_idempotent(self):
        _, private_key, public_key = self._pair(0)
        directory = ThumbprintDirectory([private_key])
        directory.add_key(public_key)
        self.assertEqual(len(directory), 1)
        # both representations still resolve to the originally registered key
        self.assertIs(directory.get(public_key.thumbprint_uri()), private_key)
        self.assertIs(directory.get_by_thumbprint(public_key.thumbprint()), private_key)

    def test_shared_kid_keeps_both_keys(self):
        # RFC 7517 does not require kids to be unique. Two distinct keys may
        # share a kid; the unique thumbprint/URI indexes still separate them,
        # and the legacy kid lookup returns the first registered key (like KeySet).
        first = OctKey.import_key("first-secret-value", parameters={"kid": "shared"})
        second = OctKey.import_key("second-secret-value", parameters={"kid": "shared"})
        self.assertNotEqual(first.thumbprint(), second.thumbprint())
        directory = ThumbprintDirectory([first, second])

        self.assertEqual(len(directory), 2)
        self.assertIs(directory.get_by_kid("shared"), first)
        # each key stays uniquely reachable through its own thumbprint and URI
        self.assertIs(directory.get_by_thumbprint(second.thumbprint()), second)
        self.assertIs(directory.get_by_thumbprint_uri(second.thumbprint_uri()), second)
        self.assertIs(directory.get_by_thumbprint(first.thumbprint()), first)

    def test_parameter_filtering(self):
        enc_key = OctKey.import_key("secret", parameters={"use": "enc", "kid": "enc"})
        sig_key = OctKey.import_key("secret", parameters={"use": "sig", "kid": "sig"})
        directory = ThumbprintDirectory([enc_key, sig_key])

        self.assertIs(
            directory.get(enc_key.thumbprint_uri(), parameters={"use": "enc"}),
            enc_key,
        )
        self.assertRaises(
            InvalidKeyIdError,
            directory.get,
            enc_key.thumbprint_uri(),
            {"use": "sig"},
        )

    def test_from_key_set_and_export(self):
        key_set = KeySet([RSAKey.generate_key(), ECKey.generate_key("P-256")])
        directory = ThumbprintDirectory.from_key_set(key_set)
        self.assertEqual(len(directory), 2)

        exported = directory.key_set()
        self.assertIsInstance(exported, KeySet)
        self.assertEqual(len(exported.keys), 2)
        for key in key_set:
            self.assertIs(directory.get(key.thumbprint_uri()), key)

    def test_indexes_report_is_stable(self):
        _, private_key, public_key = self._pair(2)
        directory = ThumbprintDirectory([private_key])
        first = directory.indexes()
        second = ThumbprintDirectory([public_key]).indexes()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0].thumbprint, second[0].thumbprint)
        self.assertEqual(first[0].thumbprint_uri, second[0].thumbprint_uri)
