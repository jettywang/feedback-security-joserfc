import re
from typing import Any, Literal, NamedTuple

from .._rfc7638 import calculate_thumbprint

JWK_THUMBPRINT_URN = "urn:ietf:params:oauth:jwk-thumbprint"

DigestMethod = Literal["sha256", "sha384", "sha512"]

_DIGEST_HASH_NAMES: dict[str, DigestMethod] = {
    "sha-256": "sha256",
    "sha-384": "sha384",
    "sha-512": "sha512",
}

_THUMBPRINT_URI_RE = re.compile(
    r"^urn:ietf:params:oauth:jwk-thumbprint:(?P<hash>sha-256|sha-384|sha-512):(?P<thumbprint>[A-Za-z0-9_-]+)$"
)


class ParsedThumbprintURI(NamedTuple):
    """Parsed components of a JWK thumbprint URI (RFC 9278)."""

    digest_method: DigestMethod
    thumbprint: str


def calculate_thumbprint_uri(
    value: dict[str, Any],
    digest_method: Literal["sha256", "sha384", "sha512"] = "sha256",
) -> str:
    """Calculate JWK thumbprint URI, defined by RFC9278.

    .. code-block:: python

        from joserfc import jwk

        jwk.thumbprint({
            'kty': 'oct',
            'k': 'sTBpI_oCHSyW-n0exSwhzNHwU9FGRioPauxWA84bnRU',
        })
        # 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:DCdRGGDKvhAJgmVlCp6tosc2T9ELtd30S_15vn8bhrI'
    """
    thumbprint = calculate_thumbprint(value, digest_method=digest_method)
    return concat_thumbprint_uri(thumbprint, digest_method=digest_method)


def concat_thumbprint_uri(value: str, digest_method: Literal["sha256", "sha384", "sha512"]) -> str:
    method = digest_method.replace("sha", "sha-")
    return f"{JWK_THUMBPRINT_URN}:{method}:{value}"


def parse_thumbprint_uri(value: str) -> ParsedThumbprintURI:
    """Split a JWK thumbprint URI into its digest algorithm and bare thumbprint.

    :raises ValueError: if ``value`` is not a well-formed RFC 9278 thumbprint URI
    """
    match = _THUMBPRINT_URI_RE.match(value)
    if match is None:
        raise ValueError("Invalid JWK thumbprint URI")
    return ParsedThumbprintURI(
        digest_method=_DIGEST_HASH_NAMES[match.group("hash")],
        thumbprint=match.group("thumbprint"),
    )


def is_thumbprint_uri(value: str) -> bool:
    """Return ``True`` when ``value`` is a well-formed JWK thumbprint URI."""
    return _THUMBPRINT_URI_RE.match(value) is not None


def normalize_thumbprint_identifier(value: str) -> str:
    """Return the bare RFC 7638 thumbprint for either representation.

    A bare thumbprint is returned unchanged so that legacy directory indexes
    keep working; a thumbprint URI is reduced to its trailing digest value.
    """
    if is_thumbprint_uri(value):
        return parse_thumbprint_uri(value).thumbprint
    return value
