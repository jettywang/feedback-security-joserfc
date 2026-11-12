from collections.abc import Collection, Mapping
from typing import Any, overload

from ._rfc7515.compact import (
    detach_compact_content,
    sign_compact,
    verify_compact,
)
from ._rfc7515.json import (
    VerificationBudget,
    detach_json_content,
    verify_flattened_json,
    verify_general_json,
    verify_signature,
)
from ._rfc7515.model import (
    CompactSignature,
    FlattenedJSONSignature,
    GeneralJSONSignature,
    HeaderMember,
    JWSAlgModel,
)
from ._rfc7515.registry import (
    JWSRegistry,
    construct_registry,
    default_registry,
)
from ._rfc7515.types import (
    FlattenedJSONSerialization,
    GeneralJSONSerialization,
    HeaderDict,
)
from ._rfc7797.compact import (
    extract_rfc7515_compact as extract_compact,
)
from ._rfc7797.compact import (
    sign_rfc7515_compact,
)
from ._rfc7797.json import (
    extract_general_json,
    sign_flattened_json,
    sign_general_json,
)
from ._rfc7797.json import extract_rfc7797_json as extract_flattened_json
from ._rfc7797.util import is_rfc7797_enabled
from .errors import BadSignatureError, MissingKeyError, VerificationBudgetExceededError
from .jwa import setup_jws_algorithms
from .jwk import Key, KeyFlexible, KeySet, guess_key
from .registry import Header
from .util import to_bytes

__all__ = [
    # types
    "HeaderDict",
    "GeneralJSONSerialization",
    "FlattenedJSONSerialization",
    # modules
    "JWSRegistry",
    "HeaderMember",
    "CompactSignature",
    "GeneralJSONSignature",
    "FlattenedJSONSignature",
    "VerificationBudget",
    "RoleVerificationResult",
    # methods
    "serialize_compact",
    "deserialize_compact",
    "extract_compact",
    "validate_compact",
    "serialize_json",
    "deserialize_json",
    "verify_json_roles",
    "detach_content",
    # consts
    "default_registry",
]

setup_jws_algorithms()


def serialize_compact(
    protected: Header,
    payload: bytes | str,
    private_key: KeyFlexible | None,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> str:
    """Generate a JWS Compact Serialization. The JWS Compact Serialization
    represents digitally signed or MACed content as a compact, URL-safe
    string, per Section 7.1.

    .. code-block:: text

        BASE64URL(UTF8(JWS Protected Header)) || '.' ||
        BASE64URL(JWS Payload) || '.' ||
        BASE64URL(JWS Signature)

    :param protected: protected header part of the JWS, in dict
    :param payload: payload data of the JWS, in bytes
    :param private_key: a flexible private key to sign the signature
    :param algorithms: a collection (list, tuple, or set) of allowed algorithms
    :param registry: a JWSRegistry to use
    :return: JWS in str
    """
    if registry is None:
        registry = construct_registry(algorithms)

    registry.check_header(protected)

    is_rfc7797 = is_rfc7797_enabled(protected)
    obj = CompactSignature(protected, to_bytes(payload))
    alg: JWSAlgModel = registry.get_alg(protected["alg"])

    # "none" algorithm requires no key
    key: Key | None = None
    if alg.name != "none":
        if private_key is None:
            raise MissingKeyError()

        key = guess_key(private_key, obj, True, use="sig")
        alg.check_key(key)

    if is_rfc7797:
        out = sign_rfc7515_compact(obj, alg, key)
    else:
        out = sign_compact(obj, alg, key)
    return out.decode("utf-8")


def validate_compact(
    obj: CompactSignature,
    public_key: KeyFlexible | None,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> bool:
    """Validate the JWS Compact Serialization with the given key.
    This method is usually used together with ``extract_compact``.

    :param obj: object of the JWS Compact Serialization
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a collection (list, tuple, or set) of allowed algorithms
    :param registry: a JWSRegistry to use
    """
    if registry is None:
        registry = construct_registry(algorithms)

    headers = obj.headers()
    registry.check_header(headers)
    alg: JWSAlgModel = registry.get_alg(headers["alg"])

    # "none" algorithm requires no key
    if headers["alg"] == "none":
        return verify_compact(obj, alg, None)

    if public_key is None:
        raise MissingKeyError()

    key: Key = guess_key(public_key, obj, use="sig")
    alg.check_key(key)
    return verify_compact(obj, alg, key)


def deserialize_compact(
    value: bytes | str,
    public_key: KeyFlexible | None,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
    payload: bytes | str | None = None,
) -> CompactSignature:
    """Extract and validate the JWS Compact Serialization (in string, or bytes)
    with the given key. An JWE Compact Serialization looks like:

    .. code-block:: text
        :caption: line breaks for display purposes only

        eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
        .
        eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
        cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
        .
        dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

    :param value: a string (or bytes) of the JWS Compact Serialization
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a collection (list, tuple, or set) of allowed algorithms
    :param registry: a JWSRegistry to use
    :param payload: optional payload, required with detached content
    :raises BadSignatureError: when signature verification fails
    :return: object of the CompactSignature
    """
    obj = extract_compact(to_bytes(value), payload, registry)
    if not validate_compact(obj, public_key, algorithms, registry):
        raise BadSignatureError()
    return obj


@overload
def serialize_json(
    members: list[HeaderDict],
    payload: bytes | str,
    private_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> GeneralJSONSerialization: ...


@overload
def serialize_json(
    members: HeaderDict,
    payload: bytes | str,
    private_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> FlattenedJSONSerialization: ...


def serialize_json(
    members: HeaderDict | list[HeaderDict],
    payload: bytes | str,
    private_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> GeneralJSONSerialization | FlattenedJSONSerialization:
    """Generate a JWS JSON Serialization (in dict). The JWS JSON Serialization
    represents digitally signed or MACed content as a JSON object. This representation
    is neither optimized for compactness nor URL-safe.

    A general JWS JSON Serialization contains:

    payload
        The "payload" member MUST be present and contain the value
        BASE64URL(JWS Payload).

    signatures
        The "signatures" member value MUST be an array of JSON objects.
        Each object represents a signature or MAC over the JWS Payload and
        the JWS Protected Header.

    A flatten JWS JSON Serialization looks like:

    .. code-block:: text

        {
            "payload":"<payload contents>",
            "protected":"<integrity-protected header contents>",
            "header":<non-integrity-protected header contents>,
            "signature":"<signature contents>"
        }
    """
    if registry is None:
        registry = construct_registry(algorithms)

    def find_key(obj: HeaderMember) -> Key:
        return guess_key(private_key, obj, True, use="sig")

    _payload = to_bytes(payload)
    if isinstance(members, list):
        _members = [HeaderMember(**member) for member in members]
        return sign_general_json(_members, _payload, registry, find_key)
    else:
        member = HeaderMember(**members)
        return sign_flattened_json(member, _payload, registry, find_key)


@overload
def deserialize_json(
    value: GeneralJSONSerialization,
    public_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> GeneralJSONSignature: ...


@overload
def deserialize_json(
    value: FlattenedJSONSerialization,
    public_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> FlattenedJSONSignature: ...


def deserialize_json(
    value: GeneralJSONSerialization | FlattenedJSONSerialization,
    public_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> GeneralJSONSignature | FlattenedJSONSignature:
    """Extract and validate the JWS (in string) with the given key.

    :param value: a dict of the JSON signature
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a collection (list, tuple, or set) of allowed algorithms
    :param registry: a JWSRegistry to use
    :return: object of GeneralJSONSignature or FlattenedJSONSignature
    :raises BadSignatureError: when signature verification fails
    """
    if registry is None:
        registry = construct_registry(algorithms)

    def find_key(obj: HeaderMember) -> Key:
        return guess_key(public_key, obj, use="sig")

    if "signatures" in value:
        general_obj = extract_general_json(value, registry)
        if not verify_general_json(general_obj, registry, find_key):
            raise BadSignatureError()
        return general_obj
    else:
        flattened_obj = extract_flattened_json(value, registry)
        if not verify_flattened_json(flattened_obj, registry, find_key):
            raise BadSignatureError()
        return flattened_obj


class RoleVerificationResult:
    """The result of :func:`verify_json_roles`. It reports which required
    roles presented a valid signature, and how the verification budget
    was spent."""

    def __init__(self, roles: dict[str, bool], verifications: int, budget_exhausted: bool) -> None:
        #: per required role, True if a valid signature of that role was found
        self.roles = roles
        #: number of actual verification operations performed on the message
        self.verifications = verifications
        #: True when the verification stopped because the budget was exhausted
        self.budget_exhausted = budget_exhausted

    @property
    def approved(self) -> bool:
        """True when every required role presented a valid signature."""
        return all(self.roles.values())

    def __repr__(self) -> str:
        return (
            f"RoleVerificationResult(approved={self.approved}, roles={self.roles}, "
            f"verifications={self.verifications}, budget_exhausted={self.budget_exhausted})"
        )


def verify_json_roles(
    value: GeneralJSONSerialization,
    role_keys: Mapping[str, KeyFlexible],
    required_roles: Collection[str] | None = None,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
    max_verifications: int | None = None,
) -> RoleVerificationResult:
    """Verify a general JWS JSON Serialization of an approval message that
    carries signatures of multiple roles. The message is approved only when
    every required role contributed at least one valid signature. A single
    signature can satisfy one role only.

    The application assigns the available public key(s) to each role with
    ``role_keys``. A signature is attributed to a role by the ``kid`` header
    when both the signature and the role's keys declare key IDs; otherwise
    every signature is tried with the role's key.

    An optional budget (``max_verifications``) limits how many verification
    operations this single message may consume. Every actual verification is
    counted on the budget, including failed ones. When the budget runs out,
    the verification stops and the result reports ``budget_exhausted``.

    .. code-block:: python

        >>> result = verify_json_roles(
        ...     message,
        ...     role_keys={"manager": manager_key, "auditor": auditor_key},
        ...     max_verifications=4,
        ... )
        >>> result.approved
        True

    :param value: a dict of the general JWS JSON Serialization
    :param role_keys: a mapping of role name to the role's public key(s)
    :param required_roles: roles that MUST sign the message, defaults to
        all the roles in ``role_keys``
    :param algorithms: a collection (list, tuple, or set) of allowed algorithms
    :param registry: a JWSRegistry to use
    :param max_verifications: maximum verification operations the message may
        consume, ``None`` means unlimited
    :return: object of RoleVerificationResult
    """
    if registry is None:
        registry = construct_registry(algorithms)

    if required_roles is None:
        roles = list(role_keys)
    else:
        roles = list(dict.fromkeys(required_roles))

    missing_roles = [role for role in roles if role not in role_keys]
    if missing_roles:
        raise ValueError(f"Missing keys for roles: {missing_roles}")

    obj = extract_general_json(value, registry)
    payload_segment = obj.segments["payload"]
    budget = VerificationBudget(max_verifications)

    verified = dict.fromkeys(roles, False)
    consumed: set[int] = set()
    budget_exhausted = False

    for role in roles:
        key_source = role_keys[role]

        def find_key(member: HeaderMember, _source: KeyFlexible = key_source) -> Key:
            return guess_key(_source, member, use="sig")

        for index, (member, signature) in enumerate(zip(obj.members, obj.signatures)):
            if index in consumed or not _role_key_matches(member, key_source):
                continue
            try:
                verified_one = verify_signature(member, signature, payload_segment, registry, find_key, budget)
            except VerificationBudgetExceededError:
                budget_exhausted = True
                break
            if verified_one:
                verified[role] = True
                consumed.add(index)
                break
        if budget_exhausted:
            break

    return RoleVerificationResult(verified, budget.used, budget_exhausted)


def _role_key_matches(member: HeaderMember, key_source: KeyFlexible) -> bool:
    """A signature can only belong to a role if its ``kid`` matches one of
    the role's keys. When either side does not declare a key ID, the
    signature is considered a candidate for the role."""
    sig_kid = member.headers().get("kid")
    if sig_kid is None:
        return True

    kids: set[str] = set()
    if isinstance(key_source, KeySet):
        kids = {key.kid for key in key_source.keys if key.kid}
    else:
        kid = getattr(key_source, "kid", None)
        if kid:
            kids = {kid}
    return not kids or sig_kid in kids


@overload
def detach_content(value: str) -> str: ...


@overload
def detach_content(value: GeneralJSONSerialization) -> dict[str, Any]: ...


@overload
def detach_content(value: FlattenedJSONSerialization) -> dict[str, Any]: ...


def detach_content(value: Any) -> Any:
    """In some contexts, it is useful to integrity-protect content that is
    not itself contained in a JWS. This method is an implementation of
    https://www.rfc-editor.org/rfc/rfc7515#appendix-F

    It is used to detach the content of the compact and JSON serialization.

    .. code-block:: python

        >>> from joserfc import jws
        >>> from joserfc.jwk import OctKey
        >>> key = OctKey.import_key("secret")
        >>> encoded_text = jws.serialize_compact({"alg": "HS256"}, b"hello", key)
        >>> jws.detach_content(encoded_text)
        'eyJhbGciOiJIUzI1NiJ9..UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A'

    You can also detach the JSON serialization:

    .. code-block:: python

        >>> obj = jws.serialize_json({"protected": {"alg": "HS256"}}, b"hello", key)
        >>> jws.detach_content(obj)
        {
            'payload': '',
            'signature': 'UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A',
            'protected': 'eyJhbGciOiJIUzI1NiJ9'
        }
    """
    if isinstance(value, str):
        return detach_compact_content(value)
    return detach_json_content(value)
