from unittest import TestCase

from joserfc import jwe, jws, jwt
from joserfc.errors import (
    BadSignatureError,
    DecodeError,
    InvalidClaimError,
    InvalidPayloadError,
    MissingClaimError,
    UnsupportedAlgorithmError,
    UnsupportedHeaderError,
)
from joserfc.jwk import GuestProtocol, Key, OctKey, import_key


def use_embedded_jwk(obj: GuestProtocol) -> Key:
    headers = obj.headers()
    return import_key(headers["jwk"])


class TestJWT(TestCase):
    oct_key = OctKey.generate_key()

    def test_default_type(self):
        data = jwt.encode({"alg": "HS256"}, {"sub": "a"}, self.oct_key)
        token = jwt.decode(data, self.oct_key)
        self.assertEqual(token.header["typ"], "JWT")

        data = jwt.encode({"alg": "HS256"}, {"sub": "a"}, self.oct_key, default_type=None)
        token = jwt.decode(data, self.oct_key)
        self.assertNotIn("typ", token.header)

        data = jwt.encode({"alg": "HS256"}, {"sub": "a"}, self.oct_key, default_type="jwt+at")
        token = jwt.decode(data, self.oct_key)
        self.assertEqual(token.header["typ"], "jwt+at")

    def test_invalid_payload(self):
        data = jws.serialize_compact({"alg": "HS256"}, b"hello", self.oct_key)
        self.assertRaises(InvalidPayloadError, jwt.decode, data, self.oct_key)

    def test_payload_must_be_a_json_object(self):
        for payload in (b"[1, 2, 3]", b"null", b'"claims"', b"1", b"true"):
            with self.subTest(payload=payload):
                data = jws.serialize_compact({"alg": "HS256"}, payload, self.oct_key)
                self.assertRaises(InvalidPayloadError, jwt.decode, data, self.oct_key)

    def test_claims_registry(self):
        data = jwt.encode({"alg": "HS256"}, {"sub": "a"}, self.oct_key)
        token = jwt.decode(data, self.oct_key)

        claims_registry = jwt.JWTClaimsRegistry(iss={"essential": True})
        self.assertRaises(MissingClaimError, claims_registry.validate, token.claims)

        data = jwt.encode({"alg": "HS256"}, {"iss": "a"}, self.oct_key)
        obj = jwt.decode(data, self.oct_key)
        self.assertEqual(obj.claims["iss"], "a")

    def test_jwe_format(self):
        header = {"alg": "A128KW", "enc": "A128GCM"}
        claims = {"iss": "https://authlib.org"}
        key = OctKey.generate_key(128)
        registry = jwe.JWERegistry()
        result = jwt.encode(header, claims, key, registry=registry)
        self.assertEqual(result.count("."), 4)

        token = jwt.decode(result, key, registry=registry)
        self.assertEqual(token.claims, claims)

    def test_using_registry(self):
        key = OctKey.generate_key(128)
        value1 = jwt.encode({"alg": "HS256"}, {"sub": "a"}, key, registry=jws.JWSRegistry())
        jwt.decode(value1, key, registry=jws.JWSRegistry())
        value2 = jwt.encode({"alg": "A128KW", "enc": "A128GCM"}, {"sub": "a"}, key, registry=jwe.JWERegistry())
        jwt.decode(value2, key, registry=jwe.JWERegistry())

        self.assertRaises(
            KeyError,
            jwt.encode,
            {"alg": "HS256"},
            {"sub": "a"},
            key,
            registry=jwe.JWERegistry(),
        )
        self.assertRaises(
            UnsupportedHeaderError,
            jwt.encode,
            {"alg": "A128KW", "enc": "A128GCM"},
            {"sub": "a"},
            key,
            registry=jws.JWSRegistry(),
        )
        self.assertRaises(
            ValueError,
            jwt.decode,
            value1,
            key,
            registry=jwe.JWERegistry(),
        )
        self.assertRaises(
            DecodeError,
            jwt.decode,
            value2,
            key,
            registry=jws.JWSRegistry(),
        )

    def test_algorithms_accepts_any_collection(self):
        # ``algorithms`` only needs to support ``in`` and truthiness, so any
        # collection works, not just a list.
        data = jwt.encode({"alg": "HS256"}, {"sub": "a"}, self.oct_key)
        for algorithms in (["HS256"], ("HS256",), {"HS256"}, frozenset({"HS256"})):
            token = jwt.decode(data, self.oct_key, algorithms=algorithms)
            self.assertEqual(token.claims["sub"], "a")

    def test_algorithms_collection_rejects_disallowed(self):
        data = jwt.encode({"alg": "HS256"}, {"sub": "a"}, self.oct_key)
        # a disallowed algorithm is still rejected when given as a non-list
        self.assertRaises(
            UnsupportedAlgorithmError,
            jwt.decode,
            data,
            self.oct_key,
            ("HS384",),
        )

    def test_claims_view(self):
        claims = {
            "jti": "task-1",
            "iss": "https://issuer.example",
            "flags": {"retry": True, "notify": False, "debug": True},
            "scope": "internal",
        }
        data = jwt.encode({"alg": "HS256"}, claims, self.oct_key)
        token = jwt.decode(data, self.oct_key)

        claims_registry = jwt.JWTClaimsRegistry(jti={"essential": True}, iss={"essential": True})
        claims_registry.validate(token.claims)

        view = jwt.select_claims_view(
            token.claims,
            {"jti": None, "iss": None, "flags": {"retry": None, "notify": None}, "unknown": None},
        )
        # only the declared fields are exposed; unknown fields and private
        # claims ("scope", "flags.debug") stay on the validation side
        self.assertEqual(
            view,
            {"jti": "task-1", "iss": "https://issuer.example", "flags": {"retry": True, "notify": False}},
        )

        # the view is independent: mutating it does not alter the claims
        view["flags"]["retry"] = False
        view["jti"] = "task-2"
        self.assertEqual(token.claims["flags"]["retry"], True)
        self.assertEqual(token.claims["jti"], "task-1")

    def test_claims_view_flat_fields(self):
        claims = {"jti": "task-1", "iss": "a", "extra": [1, 2]}
        view = jwt.select_claims_view(claims, ["jti", "extra"])
        self.assertEqual(view, {"jti": "task-1", "extra": [1, 2]})
        view["extra"].append(3)
        self.assertEqual(claims["extra"], [1, 2])

    def test_no_claims_view_on_bad_signature(self):
        data = jwt.encode({"alg": "HS256"}, {"jti": "task-1"}, self.oct_key)
        other_key = OctKey.generate_key()
        with self.assertRaises(BadSignatureError):
            jwt.decode(data, other_key)

    def test_no_claims_view_on_invalid_claims(self):
        data = jwt.encode({"alg": "HS256"}, {"jti": "task-1", "iss": "b"}, self.oct_key)
        token = jwt.decode(data, self.oct_key)
        claims_registry = jwt.JWTClaimsRegistry(iss={"essential": True, "value": "a"})
        with self.assertRaises(InvalidClaimError):
            claims_registry.validate(token.claims)

    def test_with_embedded_jwk(self):
        value = (
            "eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJ4IjoiVU05ZzVuS25aWFlvdldBbE"
            "03NmNMejl2VG96UmpfX0NIVV9kT2wtZ09vRSIsInkiOiJkczhhZVF3MWwy"
            "Y0RDQTdiQ2tPTnZ3REtwWEFidFhqdnFDbGVZSDhXc19VIiwia3R5IjoiRU"
            "MifSwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJ1cm46ZXhhbXBsZTppc3N1Z"
            "XIiLCJhdWQiOiJ1cm46ZXhhbXBsZTphdWRpZW5jZSIsImlhdCI6MTYwNDU"
            "4MDc5NH0.60boak3_dErnW47ZPty1C0nrjeVq86EN_eK0GOq6K8w2OA0th"
            "KoBxFK4j-NuU9yZ_A9UKGxPT_G87DladBaV9g"
        )
        token = jwt.decode(value, use_embedded_jwk)
        self.assertEqual(token.claims["iss"], "urn:example:issuer")
