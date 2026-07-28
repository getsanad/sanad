"""Interop tests locking the byte formats against the Go implementation.

These vectors are fixed by the Go code (workload/, delegation/, cmd/passport/).
The instance key seed is the 32 bytes 0x01..0x20.

The same values are pinned Go-side in workload/interop_test.go, which is what CI runs;
changing one without the other is a wire break. Update all three suites together.
"""

import base64
import json
import unittest

from sanad import (
    CTX_INSTANCE_PROOF,
    HEADER_CREDENTIAL,
    HEADER_DELEGATION,
    HEADER_PROOF,
    PassportClient,
    bootstrap_evidence,
    enroll,
    generate_instance_key,
    proof,
    public_key_of,
    sigctx_message,
)
from sanad import _b64url_decode, _b64url_encode  # internal helpers under test


# The 32-byte seed 0x01..0x20, as base64url (no padding).
SEED_B64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
# The 64-byte seed||pub form, as base64url.
PRIV64_B64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB5tVYuj-ZU-UB4sRLoqYunkB-FOuaVvtfg45ELrQSWZA"
# Expected public key (base64url of the raw 32-byte public key).
PUB_B64 = "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"

# Enrollment nonce 0x00..0x1f, and the evidence Go's workload.BootstrapEvidence produces
# for it with token "boot-token" and PUB_B64.
NONCE_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
EXPECTED_EVIDENCE = "umfR1kxOzPGX1ZFOK5pgnnRtnxSm-q3nE-Qx6DPsI1o"

PRINCIPAL_TOKEN = "test-principal-token"
# The proof is over the domain-separated signing input, not the bare token.
EXPECTED_PROOF = "_xyI6J0jruF9VJx5RZimoWtBtrH_7lFTueCgCdeSllnwDcTP5bxCQ9ponOj9OZSbidfO-89TiuC8QYwKBYmlDw"
# That signing input, as hex: 8-byte big-endian length || context label || token.
EXPECTED_PROOF_INPUT = (
    "000000000000001773616e61642f696e7374616e63652d70726f6f662f76"
    "31746573742d7072696e636970616c2d746f6b656e"
)

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

    def test_sigctx_message_layout(self):
        self.assertEqual(sigctx_message("abc", b"xy"), b"\x00" * 7 + b"\x03" + b"abcxy")
        # The length prefix is what disambiguates the split between label and message.
        self.assertNotEqual(sigctx_message("ab", b"c"), sigctx_message("a", b"bc"))

    def test_proof_signing_input_vector(self):
        got = sigctx_message(CTX_INSTANCE_PROOF, PRINCIPAL_TOKEN.encode("utf-8"))
        print("proof signing input =", got.hex())
        self.assertEqual(got.hex(), EXPECTED_PROOF_INPUT)

    def test_proof_vector(self):
        got = proof(SEED_B64, PRINCIPAL_TOKEN)
        print("proof =", got)
        self.assertEqual(got, EXPECTED_PROOF)

    def test_proof_is_domain_separated_not_over_the_bare_token(self):
        from sanad import _b64url_encode, _load_private

        priv = _load_private(SEED_B64)
        # The pre-domain-separation form: a raw signature over the token bytes. It must NOT
        # be what the SDK sends — that signature would equally be a delegation hop signed by
        # the same instance key, so the gateway rejects it.
        bare = _b64url_encode(priv.sign(PRINCIPAL_TOKEN.encode("utf-8")))
        self.assertNotEqual(proof(SEED_B64, PRINCIPAL_TOKEN), bare)

        tagged = _b64url_encode(
            priv.sign(sigctx_message(CTX_INSTANCE_PROOF, PRINCIPAL_TOKEN.encode("utf-8")))
        )
        self.assertEqual(proof(SEED_B64, PRINCIPAL_TOKEN), tagged)

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


class TestEnrollment(unittest.TestCase):
    def test_bootstrap_evidence_matches_go_vector(self):
        evidence = bootstrap_evidence(
            "boot-token", _b64url_decode(NONCE_B64), _b64url_decode(PUB_B64)
        )
        self.assertEqual(_b64url_encode(evidence), EXPECTED_EVIDENCE)

    def test_bootstrap_evidence_is_bound_to_nonce_and_key(self):
        nonce = _b64url_decode(NONCE_B64)
        pub = _b64url_decode(PUB_B64)
        # Changing any input must change the evidence — otherwise a captured enrollment
        # could be replayed with a different key, which is exactly what this prevents.
        for token, n, p in [
            ("boot-token", nonce, bytes(32)),
            ("boot-token", bytes(32), pub),
            ("other-token", nonce, pub),
        ]:
            self.assertNotEqual(
                _b64url_encode(bootstrap_evidence(token, n, p)), EXPECTED_EVIDENCE
            )

    def test_enroll_fetches_a_nonce_then_posts_key_bound_evidence(self):
        import urllib.request as ur

        calls = []

        class FakeResp:
            def __init__(self, body):
                self._body = body.encode("utf-8")

            def read(self):
                return self._body

            def getcode(self):
                return 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, *args, **kwargs):
            calls.append((req.full_url, json.loads(req.data.decode("utf-8"))))
            if req.full_url.endswith("/enroll/nonce"):
                return FakeResp(json.dumps({"nonce": NONCE_B64, "expires_in": 120}))
            return FakeResp(CREDENTIAL_TEXT)

        real_urlopen = ur.urlopen
        ur.urlopen = fake_urlopen
        try:
            result = enroll("https://authority.example.com/", "boot-token", PUB_B64)
        finally:
            ur.urlopen = real_urlopen

        self.assertEqual(result["credential"], CREDENTIAL_TEXT)
        self.assertEqual(result["agent_id"], "agent-1")

        # Two legs: the nonce, then the enrollment.
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], "https://authority.example.com/enroll/nonce")
        url, body = calls[1]
        self.assertEqual(url, "https://authority.example.com/enroll")
        self.assertEqual(body["nonce"], NONCE_B64)
        self.assertEqual(body["public_key"], PUB_B64)
        # The bootstrap token is NOT on the wire; the evidence is a MAC over nonce + key.
        self.assertEqual(body["evidence"], EXPECTED_EVIDENCE)
        self.assertNotIn("boot-token", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
