"""Interop tests locking the byte formats against the Go implementation.

These vectors are fixed by the Go code (workload/, delegation/, cmd/passport/).
The instance key seed is the 32 bytes 0x01..0x20.
"""

import base64
import json
import unittest

from sanad import (
    HEADER_CREDENTIAL,
    HEADER_DELEGATION,
    HEADER_PROOF,
    PassportClient,
    generate_instance_key,
    proof,
    public_key_of,
)
from sanad import _b64url_decode, _b64url_encode  # internal helpers under test


# The 32-byte seed 0x01..0x20, as base64url (no padding).
SEED_B64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
# The 64-byte seed||pub form, as base64url.
PRIV64_B64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB5tVYuj-ZU-UB4sRLoqYunkB-FOuaVvtfg45ELrQSWZA"
# Expected public key (base64url of the raw 32-byte public key).
PUB_B64 = "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"

PRINCIPAL_TOKEN = "test-principal-token"
EXPECTED_PROOF = "vS7aSzPmJd-D-AEAgbkw6oFU_0KU4rvei6aUlpCbrGn-nGkfVoqrvrV695SwkzT-id_8nXu18uleQye60FhWCQ"

CREDENTIAL_TEXT = (
    '{"AgentID":"agent-1","PublicKey":"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",'
    '"IssuedAt":"2026-07-10T00:00:00Z","NotAfter":"2026-07-10T01:00:00Z","KeyID":"ca-1","Signature":"AA=="}'
)
EXPECTED_CREDENTIAL_HEADER = (
    "eyJBZ2VudElEIjoiYWdlbnQtMSIsIlB1YmxpY0tleSI6IjNiNmEyN2JjY2ViNmE0MmQ2MmEzYThkMDJhNmYwZDczNjUzMjE1NzcxZGUyNDNhNjNhYzA0OGExOGI1OWRhMjkiLCJJc3N1ZWRBdCI6IjIwMjYtMDctMTBUMDA6MDA6MDBaIiwiTm90QWZ0ZXIiOiIyMDI2LTA3LTEwVDAxOjAwOjAwWiIsIktleUlEIjoiY2EtMSIsIlNpZ25hdHVyZSI6IkFBPT0ifQ"
)


class TestVectors(unittest.TestCase):
    def test_b64url_roundtrip_no_padding(self):
        raw = bytes(range(1, 33))
        enc = _b64url_encode(raw)
        self.assertNotIn("=", enc)
        self.assertEqual(_b64url_decode(enc), raw)

    def test_seed_b64_is_0x01_to_0x20(self):
        self.assertEqual(_b64url_decode(SEED_B64), bytes(range(1, 33)))

    def test_public_key_of_seed(self):
        got = public_key_of(SEED_B64)
        print("public_key_of(seed) =", got)
        self.assertEqual(got, PUB_B64)

    def test_public_key_of_priv64(self):
        got = public_key_of(PRIV64_B64)
        print("public_key_of(priv64) =", got)
        self.assertEqual(got, PUB_B64)

    def test_priv64_form_matches_vector(self):
        # The 64-byte seed||pub form built from the seed must equal the fixed vector.
        seed = bytes(range(1, 33))
        pub = _b64url_decode(public_key_of(SEED_B64))
        got = _b64url_encode(seed + pub)
        print("priv64 base64url =", got)
        self.assertEqual(got, PRIV64_B64)

    def test_proof_vector(self):
        got = proof(SEED_B64, PRINCIPAL_TOKEN)
        print("proof =", got)
        self.assertEqual(got, EXPECTED_PROOF)

    def test_proof_same_for_seed_and_priv64(self):
        self.assertEqual(
            proof(SEED_B64, PRINCIPAL_TOKEN),
            proof(PRIV64_B64, PRINCIPAL_TOKEN),
        )

    def test_credential_header_vector(self):
        got = _b64url_encode(CREDENTIAL_TEXT.encode("utf-8"))
        print("credential header =", got)
        self.assertEqual(got, EXPECTED_CREDENTIAL_HEADER)


class TestKeyGen(unittest.TestCase):
    def test_generate_roundtrips(self):
        key = generate_instance_key()
        self.assertIn("private_key", key)
        self.assertIn("public_key", key)
        # public_key_of(private) must equal the reported public key.
        self.assertEqual(public_key_of(key["private_key"]), key["public_key"])
        # private key decodes to the 64-byte seed||pub form.
        self.assertEqual(len(_b64url_decode(key["private_key"])), 64)
        self.assertEqual(len(_b64url_decode(key["public_key"])), 32)

    def test_seed_and_priv64_yield_same_public_key(self):
        self.assertEqual(public_key_of(SEED_B64), public_key_of(PRIV64_B64))


class TestClientHeaders(unittest.TestCase):
    def test_headers_shape_and_values(self):
        client = PassportClient(
            gateway_url="https://gw.example.com/",
            instance_key=SEED_B64,
            credential=CREDENTIAL_TEXT,
        )
        h = client.headers(PRINCIPAL_TOKEN)
        self.assertEqual(h["Authorization"], "Bearer " + PRINCIPAL_TOKEN)
        self.assertEqual(h[HEADER_CREDENTIAL], EXPECTED_CREDENTIAL_HEADER)
        self.assertEqual(h[HEADER_PROOF], EXPECTED_PROOF)
        # No delegation header unless a chain was supplied.
        self.assertNotIn(HEADER_DELEGATION, h)

    def test_delegation_header_present_when_supplied(self):
        chain_text = '{"hops":[]}'
        client = PassportClient(
            gateway_url="https://gw.example.com",
            instance_key=SEED_B64,
            credential=CREDENTIAL_TEXT,
            delegation=chain_text,
        )
        h = client.headers(PRINCIPAL_TOKEN)
        self.assertEqual(h[HEADER_DELEGATION], _b64url_encode(chain_text.encode("utf-8")))

    def test_credential_not_reserialized(self):
        # The header must be base64url of the exact bytes, not a re-serialized JSON.
        client = PassportClient(
            gateway_url="https://gw.example.com",
            instance_key=SEED_B64,
            credential=CREDENTIAL_TEXT,
        )
        h = client.headers(PRINCIPAL_TOKEN)
        decoded = _b64url_decode(h[HEADER_CREDENTIAL]).decode("utf-8")
        self.assertEqual(decoded, CREDENTIAL_TEXT)
        # Sanity: it still parses as JSON but is byte-identical to the input text.
        self.assertEqual(json.loads(decoded)["AgentID"], "agent-1")

    def test_client_accepts_dicts_from_helpers(self):
        key = generate_instance_key()
        client = PassportClient(
            gateway_url="https://gw.example.com",
            instance_key=key,  # dict form
            credential={"credential": CREDENTIAL_TEXT},  # dict form (as enroll returns)
        )
        h = client.headers(PRINCIPAL_TOKEN)
        self.assertEqual(h[HEADER_PROOF], proof(key["private_key"], PRINCIPAL_TOKEN))

    def test_request_url_construction(self):
        # Confirm the URL is /servers/{id}{path} without contacting a server, by
        # intercepting urllib at the point of building the Request.
        import urllib.request as ur

        captured = {}
        real_urlopen = ur.urlopen

        def fake_urlopen(req, *a, **k):  # noqa: ANN001
            captured["url"] = req.full_url
            captured["method"] = req.get_method()
            raise RuntimeError("stop")

        client = PassportClient(
            gateway_url="https://gw.example.com/",
            instance_key=SEED_B64,
            credential=CREDENTIAL_TEXT,
        )
        ur.urlopen = fake_urlopen
        try:
            with self.assertRaises(RuntimeError):
                client.request("srv-1", "/mcp/list", PRINCIPAL_TOKEN, method="POST")
        finally:
            ur.urlopen = real_urlopen
        self.assertEqual(captured["url"], "https://gw.example.com/servers/srv-1/mcp/list")
        self.assertEqual(captured["method"], "POST")


if __name__ == "__main__":
    unittest.main()
