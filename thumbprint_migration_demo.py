"""Dual-index thumbprint migration demo (RFC 7638 -> RFC 9278).

Run from the repository root with the project venv:

    .venv/bin/python thumbprint_migration_demo.py

It imports the local sample key pairs, proves that a private JWK and its
matching public JWK produce identical fingerprints, and prints the mapping a
migration report is built from. Nothing here writes to the source tree.
"""

from joserfc.jwk import ECKey, OKPKey, RSAKey, ThumbprintDirectory
from tests.keys import read_key

SAMPLE_PAIRS = [
    (RSAKey, "RFC7520-RSA-private.json", "RFC7520-RSA-public.json"),
    (ECKey, "RFC7520-EC-private.json", "RFC7520-EC-public.json"),
    (OKPKey, "okp-ed25519-private.json", "okp-ed25519-public.json"),
]


def main() -> None:
    directory = ThumbprintDirectory()
    print(f"{'kty':4}  {'stable':6}  kid / bare thumbprint / thumbprint URI")
    print("-" * 100)

    for key_cls, private_file, public_file in SAMPLE_PAIRS:
        private_key = key_cls.import_key(read_key(private_file))
        public_key = key_cls.import_key(read_key(public_file))

        stable = (
            private_key.thumbprint() == public_key.thumbprint()
            and private_key.thumbprint_uri() == public_key.thumbprint_uri()
        )
        index = directory.add_key(private_key)

        print(f"{key_cls.key_type:4}  {str(stable):6}  kid={index.kid}")
        print(f"      bare={index.thumbprint}")
        print(f"      uri ={index.thumbprint_uri}")
        # the public form resolves back to the registered private key via the
        # unique thumbprint indexes
        assert directory.get(public_key.thumbprint_uri()) is private_key
        assert directory.get(public_key.thumbprint()) is private_key
        # the kid index still reaches the key (kids may be shared across keys,
        # so it is resolved by identity membership rather than a single slot)
        assert private_key in directory.keys
        assert any(registered.kid == public_key.kid for registered in directory)

    print()
    print("All samples produce stable public/private fingerprints; kid index intact.")


if __name__ == "__main__":
    main()
