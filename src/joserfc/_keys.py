import random
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, ClassVar, NamedTuple, Self, TypedDict, cast

from ._rfc7517.types import AnyKey, DictKey, KeyParameters
from ._rfc7518.ec_key import ECKey
from ._rfc7518.oct_key import OctKey
from ._rfc7518.rsa_key import RSAKey
from ._rfc8037.okp_key import OKPKey
from ._rfc9278 import (
    concat_thumbprint_uri,
    is_thumbprint_uri,
)
from .errors import (
    InvalidKeyIdError,
    InvalidKeyTypeError,
    MissingKeyError,
    MissingKeyTypeError,
)
from .util import to_bytes

if TYPE_CHECKING:
    from ._rfc9278 import DigestMethod

__all__ = [
    "OctKey",
    "RSAKey",
    "ECKey",
    "OKPKey",
    "Key",
    "KeySet",
    "JWKRegistry",
    "KeySetSerialization",
    "ThumbprintDirectory",
    "ThumbprintIndex",
]

Key = OctKey | RSAKey | ECKey | OKPKey


class JWKRegistry:
    """A registry for JWK to record ``joserfc`` supported key types.
    Normally, you would use explicit key types like ``OctKey``, ``RSAKey``;
    This registry provides a way to dynamically import and generate keys.
    For instance:

    .. code-block:: python

        from joserfc.jwk import JWKRegistry

        # instead of choosing which key type to use yourself,
        # JWKRegistry can import it automatically
        data = {"kty": "oct", "k": "..."}
        key = JWKRegistry.import_key(data)
    """

    key_types: dict[str, type[Key]] = {
        OctKey.key_type: OctKey,
        RSAKey.key_type: RSAKey,
        ECKey.key_type: ECKey,
        OKPKey.key_type: OKPKey,
    }

    @classmethod
    def import_key(cls, data: AnyKey, key_type: str | None = None, parameters: KeyParameters | None = None) -> Key:
        """A class method for importing a key from bytes, string, and dict.
        When ``value`` is a dict, this method can tell the key type automatically,
        otherwise, developers SHOULD pass the ``key_type`` themselves.

        :param data: the key data in bytes, string, or dict.
        :param key_type: an optional key type in string.
        :param parameters: extra key parameters
        :return: OctKey, RSAKey, ECKey, or OKPKey
        """
        if isinstance(data, dict) and key_type is None:
            if "kty" in data:
                key_type = cast(str, data["kty"])
            else:
                raise MissingKeyTypeError("Missing key type")

        if key_type not in cls.key_types:
            raise InvalidKeyTypeError(f"Invalid key type: '{key_type}'")

        if isinstance(data, str):
            data = to_bytes(data)

        key_cls = cls.key_types[key_type]
        return key_cls.import_key(data, parameters)

    @classmethod
    def generate_key(
        cls,
        key_type: str,
        crv_or_size: str | int | None = None,
        parameters: KeyParameters | None = None,
        private: bool = True,
        auto_kid: bool = False,
    ) -> Key:
        """A class method for generating key according to the given key type.
        When ``key_type`` is "oct" and "RSA", the second parameter SHOULD be
        a key size in bits. When ``key_type`` is "EC" and "OKP", the second
        parameter SHOULD be a "crv" string.

        .. code-block:: python

            JWKRegistry.generate_key("RSA", 2048)
            JWKRegistry.generate_key("EC", "P-256")
        """
        if key_type not in cls.key_types:
            raise InvalidKeyTypeError(f"Invalid key type: '{key_type}'")

        key_cls = cls.key_types[key_type]
        return key_cls.generate_key(crv_or_size, parameters, private, auto_kid)  # type: ignore[arg-type]


class KeySetSerialization(TypedDict):
    keys: list[DictKey]


class KeySet:
    #: keys in the key set
    keys: list[Key]

    registry_cls: type[JWKRegistry] = JWKRegistry
    algorithm_keys: ClassVar[dict[str, list[str]]] = {}

    def __init__(self, keys: list[Key]):
        for key in keys:
            key.ensure_kid()
        self.keys = keys

    def __iter__(self) -> Iterator[Key]:
        return iter(self.keys)

    def __bool__(self) -> bool:
        return bool(self.keys)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeySet):
            return False
        return self.keys == other.keys

    def as_dict(self, private: bool = False, **params: Any) -> KeySetSerialization:
        keys: list[DictKey] = []

        for key in self.keys:
            # trigger key to generate kid via thumbprint
            key.ensure_kid()
            keys.append(key.as_dict(private=private, **params))
        return {"keys": keys}

    def get_by_kid(self, kid: str | None = None, parameters: KeyParameters | None = None) -> Key:
        if kid is None and len(self.keys) == 1:
            return self.keys[0]

        keys = [key for key in self.keys if key.kid == kid]
        if parameters:
            keys = list(_filter_keys_by_parameters(keys, parameters))

        if keys:
            return keys[0]
        raise InvalidKeyIdError(f"No key for kid: '{kid}'")

    def pick_random_key(self, algorithm: str | None = None, parameters: KeyParameters | None = None) -> Key | None:
        key_types = self.algorithm_keys.get(algorithm) if algorithm else None
        if key_types:
            keys = [k for k in self.keys if k.key_type in key_types]
        else:
            keys = self.keys

        if parameters:
            keys = list(_filter_keys_by_parameters(keys, parameters))

        if keys:
            return random.choice(keys)
        return None

    @classmethod
    def import_key_set(cls, value: KeySetSerialization, parameters: KeyParameters | None = None) -> Self:
        keys: list[Key] = []

        for data in value["keys"]:
            # RFC 7517, Section 5: ignore a key whose "kty" is not understood
            # rather than failing the whole set (for example a post-quantum key
            # published alongside classical ones).
            try:
                keys.append(cls.registry_cls.import_key(data, parameters=parameters))
            except InvalidKeyTypeError:
                continue

        if not keys:
            raise MissingKeyError("No keys to import")

        return cls(keys)

    @classmethod
    def generate_key_set(
        cls,
        key_type: str,
        crv_or_size: str | int,
        parameters: KeyParameters | None = None,
        private: bool = True,
        count: int = 4,
    ) -> Self:
        keys: list[Key] = []
        for _ in range(count):
            key = cls.registry_cls.generate_key(key_type, crv_or_size, parameters, private)
            keys.append(key)

        return cls(keys)


class ThumbprintIndex(NamedTuple):
    """The three stable identifiers computed for one registered key."""

    kid: str | None
    thumbprint: str
    thumbprint_uri: str
    digest_method: "DigestMethod"


class ThumbprintDirectory:
    """A dual-index key directory for the bare-thumbprint to thumbprint-URI migration.

    Each key is indexed three ways while the underlying JWK is left untouched:

    - by its bare RFC 7638 thumbprint (the legacy directory index),
    - by its algorithm-qualified RFC 9278 thumbprint URI (the new index),
    - by its existing ``kid`` so legacy callers can keep selecting the key.

    Because every form is derived from the same canonical public key material,
    a private JWK and the matching public JWK resolve to the same entries.
    """

    def __init__(self, keys: list[Key] | None = None):
        self._thumbprints: dict[str, Key] = {}
        self._thumbprint_uris: dict[str, Key] = {}
        self._kids: dict[str, list[Key]] = {}
        self._indexes: dict[str, ThumbprintIndex] = {}
        self._keys: list[Key] = []
        for key in keys or []:
            self.add_key(key)

    def __iter__(self) -> Iterator[Key]:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, identifier: object) -> bool:
        if not isinstance(identifier, str):
            return False
        if is_thumbprint_uri(identifier):
            return identifier in self._thumbprint_uris
        return identifier in self._thumbprints or identifier in self._kids

    @classmethod
    def from_key_set(cls, key_set: KeySet) -> Self:
        """Build a directory from every key already held in a :class:`KeySet`."""
        return cls(list(key_set.keys))

    @property
    def keys(self) -> list[Key]:
        """The registered keys in first-seen order."""
        return list(self._keys)

    def add_key(self, key: Key) -> ThumbprintIndex:
        """Register one key under all three indexes and return its identifiers.

        Re-adding the same key material is idempotent. An index slot that already
        points at a different key raises ``ValueError``.
        """
        thumbprint = key.thumbprint()
        digest_method = key.thumbprint_digest_method
        thumbprint_uri = concat_thumbprint_uri(thumbprint, digest_method)
        key.ensure_kid()
        kid = cast(str | None, key.kid)

        indexed = self._thumbprints.get(thumbprint)
        if indexed is not None and indexed.thumbprint() == thumbprint:
            # same canonical material: refresh aliases but keep the original key
            registered = indexed
        else:
            if indexed is not None:
                raise ValueError(f"Conflicting key for thumbprint: '{thumbprint}'")
            if thumbprint_uri in self._thumbprint_uris:
                raise ValueError(f"Conflicting key for thumbprint URI: '{thumbprint_uri}'")
            registered = key
            self._keys.append(key)
            self._thumbprints[thumbprint] = registered

        self._thumbprint_uris[thumbprint_uri] = registered
        if kid is not None and registered not in self._kids.setdefault(kid, []):
            # RFC 7517 does not require kids to be unique; keep every match,
            # mirroring KeySet.get_by_kid which returns the first registered key.
            self._kids[kid].append(registered)

        index = ThumbprintIndex(
            kid=kid,
            thumbprint=thumbprint,
            thumbprint_uri=thumbprint_uri,
            digest_method=digest_method,
        )
        self._indexes[thumbprint] = index
        return index

    def get(
        self,
        identifier: str | None,
        parameters: KeyParameters | None = None,
    ) -> Key:
        """Resolve a ``kid``, bare thumbprint, or thumbprint URI to a key.

        Thumbprint URIs are matched first (they are self-describing), then bare
        thumbprints, then the legacy ``kid`` index. ``None`` returns the only key.

        :raises InvalidKeyIdError: if no registered key matches the identifier
        """
        if identifier is None and len(self._keys) == 1:
            return self._keys[0]

        candidates: list[Key] = []
        if identifier is not None and is_thumbprint_uri(identifier):
            key = self._thumbprint_uris.get(identifier)
            if key is not None:
                candidates = [key]
        elif identifier is not None:
            key = self._thumbprints.get(identifier)
            if key is None:
                shared = self._kids.get(identifier)
                if shared:
                    key = shared[0]
            if key is not None:
                candidates = [key]

        if parameters and candidates:
            candidates = list(_filter_keys_by_parameters(candidates, parameters))

        if candidates:
            return candidates[0]
        raise InvalidKeyIdError(f"No key for identifier: '{identifier}'")

    def get_by_kid(self, kid: str | None = None, parameters: KeyParameters | None = None) -> Key:
        """Look a key up solely through the legacy ``kid`` index."""
        if kid is None and len(self._keys) == 1:
            return self._keys[0]
        shared = self._kids.get(kid) if kid else None
        candidates = list(shared) if shared else []
        if parameters and candidates:
            candidates = list(_filter_keys_by_parameters(candidates, parameters))
        if candidates:
            return candidates[0]
        raise InvalidKeyIdError(f"No key for kid: '{kid}'")

    def get_by_thumbprint(self, thumbprint: str, parameters: KeyParameters | None = None) -> Key:
        """Look a key up through the legacy bare RFC 7638 thumbprint index."""
        key = self._thumbprints.get(thumbprint)
        candidates = [key] if key is not None else []
        if parameters and candidates:
            candidates = list(_filter_keys_by_parameters(candidates, parameters))
        if candidates:
            return candidates[0]
        raise InvalidKeyIdError(f"No key for thumbprint: '{thumbprint}'")

    def get_by_thumbprint_uri(
        self,
        thumbprint_uri: str,
        parameters: KeyParameters | None = None,
    ) -> Key:
        """Look a key up through the new RFC 9278 thumbprint URI index."""
        key = self._thumbprint_uris.get(thumbprint_uri)
        candidates = [key] if key is not None else []
        if parameters and candidates:
            candidates = list(_filter_keys_by_parameters(candidates, parameters))
        if candidates:
            return candidates[0]
        raise InvalidKeyIdError(f"No key for thumbprint URI: '{thumbprint_uri}'")

    def index_of(self, key: Key) -> ThumbprintIndex:
        """Return the recorded identifiers for a registered key."""
        return self._indexes[key.thumbprint()]

    def indexes(self) -> list[ThumbprintIndex]:
        """All recorded identifiers, in key first-seen order (for migration reports)."""
        return [self._indexes[key.thumbprint()] for key in self._keys]

    def key_set(self) -> KeySet:
        """Export the registered keys as a standard :class:`KeySet`."""
        return KeySet(list(self._keys))


def _filter_keys_by_parameters(keys: list[Key], parameters: KeyParameters) -> Iterator[Key]:
    _use = parameters.get("use")
    _alg = parameters.get("alg")

    for key in keys:
        designed_use = key.get("use")
        if designed_use and _use and designed_use != _use:
            continue

        designed_alg = key.get("alg")
        if designed_alg and _alg and designed_alg != _alg:
            continue

        yield key
