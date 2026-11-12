"""Key purpose, operation and algorithm checks at the JWE call boundary.

These tests pin down where the compact and JSON serializations enforce key
restrictions, and confirm the two paths reject misconfigured keys at the
same boundary with the same error categories. Local (in-process) keys are
used for every case, and the decrypt implementation is instrumented to
record whether it was reached when a key is rejected.
"""
from unittest import TestCase
from unittest.mock import patch

from joserfc._rfc7516 import message
from joserfc.errors import (
    UnsupportedAlgorithmError,
    UnsupportedKeyOperationError,
    UnsupportedKeyUseError,
)
from joserfc.jwe import (
    FlattenedJSONEncryption,
    GeneralJSONEncryption,
    decrypt_compact,
    decrypt_json,
    encrypt_compact,
    encrypt_json,
)
from joserfc.jwk import OctKey

ALGORITHMS = ["A128KW", "A128GCM"]
PROTECTED = {"alg": "A128KW", "enc": "A128GCM"}
PLAINTEXT = b"hello"


class TestJWEKeyBoundary(TestCase):
    def setUp(self):
        self.good_key = OctKey.generate_key(128)
        self.enc_use_key = OctKey.import_key(self.good_key.as_dict(), {"use": "enc"})
        self.sig_use_key = OctKey.import_key(self.good_key.as_dict(), {"use": "sig"})
        self.wrap_ops_key = OctKey.import_key(self.good_key.as_dict(), {"key_ops": ["wrapKey"]})
        self.unwrap_ops_key = OctKey.import_key(self.good_key.as_dict(), {"key_ops": ["unwrapKey"]})

    # --- encryption -----------------------------------------------------

    def test_encrypt_accepts_allowed_use_and_ops(self):
        for key in (self.good_key, self.enc_use_key):
            with self.subTest(key=key.get("use")):
                token = encrypt_compact(PROTECTED, PLAINTEXT, key, algorithms=ALGORITHMS)
                self.assertEqual(token.count("."), 4)

        # an encrypt-only operation set is accepted on the encrypt path
        token = encrypt_compact(PROTECTED, PLAINTEXT, self.wrap_ops_key, algorithms=ALGORITHMS)
        self.assertTrue(token)

    def test_encrypt_rejects_wrong_use_on_compact_and_json(self):
        for label, build in (
            ("compact", lambda key: encrypt_compact(PROTECTED, PLAINTEXT, key, algorithms=ALGORITHMS)),
            ("flattened", self._encrypt_flattened),
            ("general", self._encrypt_general),
        ):
            with self.subTest(path=label):
                # resolved through the shared/public key argument
                self.assertRaises(UnsupportedKeyUseError, build, self.sig_use_key)

                # a key attached directly to a JSON recipient is checked too
                if label != "compact":
                    self.assertRaises(UnsupportedKeyUseError, build, None, self.sig_use_key)

    def test_encrypt_rejects_missing_operation_before_any_wrapping(self):
        # "unwrapKey" cannot perform the encrypt-side "wrapKey" operation
        with patch.object(message, "post_encrypt_recipients") as post:
            self.assertRaises(
                UnsupportedKeyOperationError,
                encrypt_compact,
                PROTECTED,
                PLAINTEXT,
                self.unwrap_ops_key,
                algorithms=ALGORITHMS,
            )
            post.assert_not_called()

        for label, build in (("flattened", self._encrypt_flattened), ("general", self._encrypt_general)):
            with self.subTest(path=label):
                with patch.object(message, "post_encrypt_recipients") as post:
                    self.assertRaises(UnsupportedKeyOperationError, build, self.unwrap_ops_key)
                    post.assert_not_called()

    # --- decryption -----------------------------------------------------

    def test_decrypt_success_result_is_identical_across_paths(self):
        compact_token = encrypt_compact(PROTECTED, PLAINTEXT, self.good_key, algorithms=ALGORITHMS)
        compact_obj = decrypt_compact(compact_token, self.good_key, algorithms=ALGORITHMS)
        self.assertEqual(compact_obj.plaintext, PLAINTEXT)

        for label, model in (("flattened", FlattenedJSONEncryption), ("general", GeneralJSONEncryption)):
            with self.subTest(path=label):
                token = self._encrypt_json(model, self.good_key)
                obj = decrypt_json(token, self.good_key, algorithms=ALGORITHMS)
                self.assertEqual(obj.plaintext, PLAINTEXT)
                self.assertEqual(obj.protected["enc"], "A128GCM")

    def test_decrypt_use_denial_blocks_decrypt_implementation(self):
        compact_token = encrypt_compact(PROTECTED, PLAINTEXT, self.good_key, algorithms=ALGORITHMS)

        with patch.object(message, "decrypt_recipient") as decrypt_recipient:
            self.assertRaises(
                UnsupportedKeyUseError,
                decrypt_compact,
                compact_token,
                self.sig_use_key,
                algorithms=ALGORITHMS,
            )
            decrypt_recipient.assert_not_called()

        for label, model in (("flattened", FlattenedJSONEncryption), ("general", GeneralJSONEncryption)):
            with self.subTest(path=label):
                token = self._encrypt_json(model, self.good_key)
                with patch.object(message, "decrypt_recipient") as decrypt_recipient:
                    self.assertRaises(
                        UnsupportedKeyUseError,
                        decrypt_json,
                        token,
                        self.sig_use_key,
                        algorithms=ALGORITHMS,
                    )
                    decrypt_recipient.assert_not_called()

    def test_decrypt_operation_denial_raises_inside_decrypt_implementation(self):
        # "wrapKey" cannot perform the decrypt-side "unwrapKey" operation;
        # the boundary "use" check passes, so the primitive is reached and
        # the operation check fires there.
        compact_token = encrypt_compact(PROTECTED, PLAINTEXT, self.good_key, algorithms=ALGORITHMS)
        with patch.object(message, "decrypt_recipient", wraps=message.decrypt_recipient) as decrypt_recipient:
            self.assertRaises(
                UnsupportedKeyOperationError,
                decrypt_compact,
                compact_token,
                self.wrap_ops_key,
                algorithms=ALGORITHMS,
            )
            decrypt_recipient.assert_called_once()

        for label, model in (("flattened", FlattenedJSONEncryption), ("general", GeneralJSONEncryption)):
            with self.subTest(path=label):
                token = self._encrypt_json(model, self.good_key)
                with patch.object(message, "decrypt_recipient", wraps=message.decrypt_recipient) as decrypt_recipient:
                    self.assertRaises(
                        UnsupportedKeyOperationError,
                        decrypt_json,
                        token,
                        self.wrap_ops_key,
                        algorithms=ALGORITHMS,
                    )
                    decrypt_recipient.assert_called_once()

    def test_decrypt_allowed_operation_reaches_decrypt_implementation(self):
        compact_token = encrypt_compact(PROTECTED, PLAINTEXT, self.good_key, algorithms=ALGORITHMS)
        with patch.object(message, "decrypt_recipient", wraps=message.decrypt_recipient) as decrypt_recipient:
            obj = decrypt_compact(compact_token, self.unwrap_ops_key, algorithms=ALGORITHMS)
            decrypt_recipient.assert_called_once()
        self.assertEqual(obj.plaintext, PLAINTEXT)

    # --- algorithm allow list ------------------------------------------

    def test_denied_algorithm_rejected_on_both_paths(self):
        narrow = ["A256KW", "A128GCM"]

        self.assertRaises(
            UnsupportedAlgorithmError,
            encrypt_compact,
            PROTECTED,
            PLAINTEXT,
            self.good_key,
            algorithms=narrow,
        )

        for label, model in (("flattened", FlattenedJSONEncryption), ("general", GeneralJSONEncryption)):
            with self.subTest(path=label):
                obj = model({"enc": "A128GCM"}, PLAINTEXT)
                obj.add_recipient({"alg": "A128KW"}, self.good_key)
                self.assertRaises(UnsupportedAlgorithmError, encrypt_json, obj, None, algorithms=narrow)

    def test_decrypt_denied_algorithm_blocks_decrypt_implementation(self):
        narrow = ["A256KW", "A128GCM"]
        compact_token = encrypt_compact(PROTECTED, PLAINTEXT, self.good_key, algorithms=ALGORITHMS)

        with patch.object(message, "decrypt_recipient") as decrypt_recipient:
            self.assertRaises(
                UnsupportedAlgorithmError,
                decrypt_compact,
                compact_token,
                self.good_key,
                algorithms=narrow,
            )
            decrypt_recipient.assert_not_called()

        for label, model in (("flattened", FlattenedJSONEncryption), ("general", GeneralJSONEncryption)):
            with self.subTest(path=label):
                token = self._encrypt_json(model, self.good_key)
                with patch.object(message, "decrypt_recipient") as decrypt_recipient:
                    self.assertRaises(
                        UnsupportedAlgorithmError,
                        decrypt_json,
                        token,
                        self.good_key,
                        algorithms=narrow,
                    )
                    decrypt_recipient.assert_not_called()

    # --- helpers --------------------------------------------------------

    def _encrypt_json(self, model, key):
        obj = model({"enc": "A128GCM"}, PLAINTEXT)
        obj.add_recipient({"alg": "A128KW"}, key)
        return encrypt_json(obj, None, algorithms=ALGORITHMS)

    def _encrypt_flattened(self, key, attached=None):
        obj = FlattenedJSONEncryption({"enc": "A128GCM"}, PLAINTEXT)
        if attached is not None:
            obj.add_recipient({"alg": "A128KW"}, attached)
            return encrypt_json(obj, None, algorithms=ALGORITHMS)
        obj.add_recipient({"alg": "A128KW"})
        return encrypt_json(obj, key, algorithms=ALGORITHMS)

    def _encrypt_general(self, key, attached=None):
        obj = GeneralJSONEncryption({"enc": "A128GCM"}, PLAINTEXT)
        if attached is not None:
            obj.add_recipient({"alg": "A128KW"}, attached)
            return encrypt_json(obj, None, algorithms=ALGORITHMS)
        obj.add_recipient({"alg": "A128KW"})
        return encrypt_json(obj, key, algorithms=ALGORITHMS)
