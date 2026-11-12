Migrating to Thumbprint URIs
============================

.. rst-class:: lead

    How to move a key directory from bare RFC 7638 thumbprints to
    algorithm-qualified RFC 9278 thumbprint URIs without breaking existing
    callers that still select keys by ``kid``.

Background
----------

A legacy key directory indexes each JWK by its **bare thumbprint** (RFC 7638):
the Base64URL-encoded SHA-256 digest of the key's canonical JSON form. A bare
thumbprint does not record which hash algorithm produced it. New clients prefer
the **thumbprint URI** (RFC 9278), which makes the digest algorithm explicit:

.. code-block:: text

    bare : 9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI
    URI  : urn:ietf:params:oauth:jwk-thumbprint:sha-256:9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI

The URI is the same digest with a fixed prefix, so the two representations are
mechanically convertible and always refer to the same key.

``joserfc`` exposes both forms on every key and adds a dual-index
:class:`~joserfc.jwk.ThumbprintDirectory` that keeps the legacy ``kid`` working
while accepting the new URI:

.. code-block:: python

    from joserfc import jwk

    directory = jwk.ThumbprintDirectory([key])

    directory.get_by_kid(key.kid)                  # legacy callers, unchanged
    directory.get_by_thumbprint(key.thumbprint())  # legacy directory index
    directory.get_by_thumbprint_uri(key.thumbprint_uri())  # new clients
    directory.get(identifier)  # accepts a kid, a bare thumbprint, or a URI

The JWK itself is never rewritten: its ``kid`` stays exactly as imported, and a
key without a ``kid`` still gets the bare thumbprint (not the URI) via
``ensure_kid``.

Stable mapping from the same public material
--------------------------------------------

Both fingerprints are computed from the *required public* members only, so a
private JWK and its matching public JWK produce identical values. The table
below is generated from the repository's local sample key pairs; importing
either the private or the public file resolves to the same directory entry.

======  ================================================  =====================================================
 kty    bare thumbprint (RFC 7638)                        thumbprint URI (RFC 9278)
======  ================================================  =====================================================
 RSA    ``9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI``  ``urn:ietf:params:oauth:jwk-thumbprint:sha-256:9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI``
 EC     ``dHri3SADZkrush5HU_50AoRhcKFryN-PI6jPBtPL55M``  ``urn:ietf:params:oauth:jwk-thumbprint:sha-256:dHri3SADZkrush5HU_50AoRhcKFryN-PI6jPBtPL55M``
 OKP    ``5V_IcL-iX5IbaNz9vg0CjXtWLZiJ94-ESnHI-HN1L2Y``  ``urn:ietf:params:oauth:jwk-thumbprint:sha-256:5V_IcL-iX5IbaNz9vg0CjXtWLZiJ94-ESnHI-HN1L2Y``
======  ================================================  =====================================================

For every row the private and public sample share the same bare thumbprint and
URI, and the URI is reproducible by prefixing the bare value with
``urn:ietf:params:oauth:jwk-thumbprint:sha-256:``. The RSA and EC samples carry
an unrelated human-readable ``kid`` (``bilbo.baggins@hobbiton.example``); the
OKP sample's ``kid`` happens to equal its bare thumbprint. All three ``kid``
values continue to resolve through the legacy index.

Note that the RSA and EC samples intentionally share the same ``kid`` even
though their key material differs. RFC 7517 does not require ``kid`` to be
unique, so the directory keeps a list of matches per ``kid`` (returning the
first, matching :meth:`~joserfc.jwk.KeySet.get_by_kid`), while the bare
thumbprint and thumbprint URI remain globally unique per key and always resolve
to exactly one entry.

Building the dual index
-----------------------

Wrap an existing :class:`~joserfc.jwk.KeySet`, or build the directory directly,
and inspect the generated mapping for an offline migration report:

.. code-block:: python

    from joserfc import jwk

    key_set = jwk.KeySet.import_key_set(jwks_document)
    directory = jwk.ThumbprintDirectory.from_key_set(key_set)

    for index in directory.indexes():
        print(index.kid, index.thumbprint, index.thumbprint_uri)

Helpers are provided for callers that receive a mix of both forms:

.. code-block:: python

    jwk.is_thumbprint_uri(value)                 # True for a RFC 9278 URI
    jwk.parse_thumbprint_uri(value)              # -> (digest_method, thumbprint)
    jwk.normalize_thumbprint_identifier(value)   # bare thumbprint for either form

When changing the directory index is enough
-------------------------------------------

Only the internal index needs to change when **consumers never see the
identifier value**:

- Keys are selected through an opaque handle, a key object, or a ``kid`` that the
  directory owns and that stays unchanged.
- Lookups already pass through one resolver; point that resolver at
  :meth:`ThumbprintDirectory.get`, which transparently accepts ``kid``, bare
  thumbprint, and URI.
- The published JWKS document keeps its existing ``kid`` members, and the
  thumbprint URI is only used as an additional *internal* lookup key.
- Signing/encryption is driven by ``alg``/``use`` rather than by matching a
  thumbprint string out of band.

In this mode the migration is additive and reversible: register both indexes,
deploy, and no caller has to change.

When consumers must be updated as well
---------------------------------------

Synchronize the callers when the identifier value **crosses a trust or system
boundary**:

- A client is expected to send or compare the thumbprint URI (for example in a
  DPoP/``cnf`` confirmation, a token header, or a metadata document). The
  receiver must run an RFC 9278-aware resolver; a bare-thumbprint lookup will
  not match the full URI string.
- Any datastore, cache key, uniqueness constraint, or allow-list stores the
  identifier text. The longer URI needs its own column/constraint; do not
  overwrite the existing ``kid`` or bare-thumbprint column during the transition.
- Code assumes ``kid == thumbprint``. That equality only holds for keys whose
  ``kid`` was auto-generated from a bare thumbprint; explicitly assigned
  ``kid`` values (such as the email-style sample above) are different and must
  keep being honored.
- Non-default digests are introduced. A URI names its hash (``sha-256``,
  ``sha-384``, ``sha-512``); consumers must honor the algorithm in the URI
  instead of hard-coding SHA-256.

Recommended rollout
-------------------

1. Build :class:`~joserfc.jwk.ThumbprintDirectory` alongside the current
   directory and verify ``indexes()`` against the legacy bare-thumbprint map.
2. Route internal lookups through :meth:`~ThumbprintDirectory.get` while keeping
   every JWK ``kid`` untouched, so legacy callers keep working.
3. Publish or accept thumbprint URIs for new clients, retaining the old index
   for the deprecation window.
4. Only after all consumers speak RFC 9278, consider retiring the bare index —
   never before, since old tokens and cached identifiers may still carry it.
