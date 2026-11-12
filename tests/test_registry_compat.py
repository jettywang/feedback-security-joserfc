"""Compatibility samples for application-configured custom JOSE headers.

These tests document and continuously verify how ``JWSRegistry`` and
``JWERegistry`` behave when an application permits its own custom header
parameters on top of the library defaults:

1. allowed: a custom header registered by the application round-trips
   through library-generated messages;
2. not configured: the same message is rejected by a registry that does
   not know the custom header;
3. missing required: a message without an application-required custom
   header is rejected by the application registry.

All messages are produced by the library itself, so the suite keeps
working as executable documentation when the registry implementation
is upgraded.
"""

import json
import unittest

from joserfc import jwe, jws
from joserfc.errors import (
    JoseError,
    MissingHeaderError,
    UnsupportedHeaderError,
)
from joserfc.jwe import JWERegistry
from joserfc.jwk import OctKey
from joserfc.jws import JWSRegistry
from joserfc.registry import HeaderParameter, HeaderRegistryDict

#: Custom header parameters permitted by the (fictional) application
#: configuration. Names are URI-based, as recommended for private
#: header parameters, to avoid collisions with registered names.
APP_HEADER_REGISTRY: HeaderRegistryDict = {
    "https://app.example/jose#tenant": HeaderParameter("Tenant identifier", "str", required=True),
    "https://app.example/jose#trace-id": HeaderParameter("Trace identifier", "str"),
}

#: Label recorded in diagnostics so operators know which configuration
#: accepted or rejected a message.
APP_CONFIG_SOURCE = "app-registry: library defaults + app custom headers"
DEFAULT_CONFIG_SOURCE = "library-default-registry"

TENANT_HEADER = "https://app.example/jose#tenant"
TRACE_HEADER = "https://app.example/jose#trace-id"

#: Values that must never appear in diagnostics output.
SECRET_HEADER_VALUE = "tenant-9f8e7d6c"
SECRET_PAYLOAD = b"payload-5a4b3c2d"


def build_app_jws_registry() -> JWSRegistry:
    return JWSRegistry(header_registry=APP_HEADER_REGISTRY)


def build_app_jwe_registry() -> JWERegistry:
    return JWERegistry(header_registry=APP_HEADER_REGISTRY)


def diagnose_header_error(
    error: JoseError,
    *,
    config_source: str,
    header: dict | None = None,
    payload: bytes | None = None,
) -> dict:
    """Build a sanitized diagnostic entry for a header-related failure.

    The entry records the configuration source and structural metadata
    only: header parameter *names* and the payload *size*. Header values
    and payload content are never included.
    """
    entry = {
        "error": error.error,
        "description": error.description,
        "config_source": config_source,
    }
    if header is not None:
        entry["header_names"] = sorted(header.keys())
    if payload is not None:
        entry["payload_size"] = len(payload)
    return entry


class JWSRegistryCompatTest(unittest.TestCase):
    key = OctKey.generate_key()

    def make_message(self, protected, registry) -> str:
        return jws.serialize_compact(protected, SECRET_PAYLOAD, self.key, registry=registry)

    def test_allowed_custom_header_round_trip(self):
        registry = build_app_jws_registry()
        protected = {
            "alg": "HS256",
            TENANT_HEADER: SECRET_HEADER_VALUE,
            TRACE_HEADER: "trace-001",
        }
        value = self.make_message(protected, registry)
        obj = jws.deserialize_compact(value, self.key, registry=registry)
        self.assertEqual(obj.payload, SECRET_PAYLOAD)
        self.assertEqual(obj.protected[TENANT_HEADER], SECRET_HEADER_VALUE)

    def test_not_configured_custom_header_rejected(self):
        app_registry = build_app_jws_registry()
        protected = {"alg": "HS256", TENANT_HEADER: SECRET_HEADER_VALUE}
        value = self.make_message(protected, app_registry)

        # the default registry does not know the custom header
        default_registry = JWSRegistry()
        with self.assertRaises(UnsupportedHeaderError):
            jws.deserialize_compact(value, self.key, registry=default_registry)
        with self.assertRaises(UnsupportedHeaderError):
            self.make_message(protected, default_registry)

    def test_unconfigured_crit_header_rejected(self):
        # a critical extension header must be understood (registered)
        app_registry = build_app_jws_registry()
        protected = {
            "alg": "HS256",
            "crit": [TENANT_HEADER],
            TENANT_HEADER: SECRET_HEADER_VALUE,
        }
        value = self.make_message(protected, app_registry)
        with self.assertRaises(UnsupportedHeaderError):
            jws.deserialize_compact(value, self.key, registry=JWSRegistry())

    def test_missing_required_custom_header_rejected(self):
        # a valid message without the application-required header,
        # produced with the default registry
        value = jws.serialize_compact({"alg": "HS256"}, SECRET_PAYLOAD, self.key)

        app_registry = build_app_jws_registry()
        with self.assertRaises(MissingHeaderError):
            jws.deserialize_compact(value, self.key, registry=app_registry)
        with self.assertRaises(MissingHeaderError):
            self.make_message({"alg": "HS256"}, app_registry)


class JWERegistryCompatTest(unittest.TestCase):
    key = OctKey.generate_key(128)

    def make_message(self, protected, registry) -> str:
        return jwe.encrypt_compact(protected, SECRET_PAYLOAD, self.key, registry=registry)

    def test_allowed_custom_header_round_trip(self):
        registry = build_app_jwe_registry()
        protected = {
            "alg": "dir",
            "enc": "A128GCM",
            TENANT_HEADER: SECRET_HEADER_VALUE,
            TRACE_HEADER: "trace-001",
        }
        value = self.make_message(protected, registry)
        obj = jwe.decrypt_compact(value, self.key, registry=registry)
        self.assertEqual(obj.plaintext, SECRET_PAYLOAD)
        self.assertEqual(obj.protected[TENANT_HEADER], SECRET_HEADER_VALUE)

    def test_not_configured_custom_header_rejected(self):
        app_registry = build_app_jwe_registry()
        protected = {"alg": "dir", "enc": "A128GCM", TENANT_HEADER: SECRET_HEADER_VALUE}
        value = self.make_message(protected, app_registry)

        default_registry = JWERegistry()
        with self.assertRaises(UnsupportedHeaderError):
            jwe.decrypt_compact(value, self.key, registry=default_registry)
        with self.assertRaises(UnsupportedHeaderError):
            self.make_message(protected, default_registry)

    def test_missing_required_custom_header_rejected(self):
        # a valid message without the application-required header,
        # produced with the default registry
        value = jwe.encrypt_compact({"alg": "dir", "enc": "A128GCM"}, SECRET_PAYLOAD, self.key)

        app_registry = build_app_jwe_registry()
        with self.assertRaises(MissingHeaderError):
            jwe.decrypt_compact(value, self.key, registry=app_registry)
        with self.assertRaises(MissingHeaderError):
            self.make_message({"alg": "dir", "enc": "A128GCM"}, app_registry)


class HeaderDiagnosticsTest(unittest.TestCase):
    key = OctKey.generate_key()

    def test_diagnostic_notes_config_source(self):
        header = {"alg": "HS256", TENANT_HEADER: SECRET_HEADER_VALUE}
        try:
            jws.serialize_compact(header, SECRET_PAYLOAD, self.key, registry=JWSRegistry())
        except UnsupportedHeaderError as error:
            entry = diagnose_header_error(
                error,
                config_source=DEFAULT_CONFIG_SOURCE,
                header=header,
                payload=SECRET_PAYLOAD,
            )
        else:  # pragma: no cover
            self.fail("expected UnsupportedHeaderError")

        self.assertEqual(entry["error"], "unsupported_header")
        self.assertEqual(entry["config_source"], DEFAULT_CONFIG_SOURCE)
        self.assertEqual(entry["header_names"], sorted(header.keys()))
        self.assertEqual(entry["payload_size"], len(SECRET_PAYLOAD))

    def test_diagnostic_never_leaks_header_values_or_payload(self):
        header = {"alg": "HS256", TENANT_HEADER: SECRET_HEADER_VALUE}
        try:
            jws.serialize_compact(header, SECRET_PAYLOAD, self.key, registry=JWSRegistry())
        except UnsupportedHeaderError as error:
            entry = diagnose_header_error(
                error,
                config_source=DEFAULT_CONFIG_SOURCE,
                header=header,
                payload=SECRET_PAYLOAD,
            )
        else:  # pragma: no cover
            self.fail("expected UnsupportedHeaderError")

        rendered = json.dumps(entry)
        self.assertNotIn(SECRET_HEADER_VALUE, rendered)
        self.assertNotIn(SECRET_PAYLOAD.decode(), rendered)


if __name__ == "__main__":
    unittest.main()
