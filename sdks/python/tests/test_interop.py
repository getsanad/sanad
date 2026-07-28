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
    CTX_CAPABILITY_HOLDER_PROOF,
    CTX_INSTANCE_PROOF,
    HEADER_CREDENTIAL,
    HEADER_DELEGATION,
    HEADER_PROOF,
    PassportClient,
    bootstrap_evidence,
    capability_holder_proof,
    enroll,
    generate_instance_key,
    proof,
    proof_binding,
    proof_payload,
    proof_target,
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

# The request one instance proof is bound to. A proof is per-request now, so the vector pins
# the request too, and holds fixed the two inputs a real proof randomizes (iat, jti).
PRINCIPAL_TOKEN = "test-principal-token"
METHOD = "POST"
TARGET = "/servers/demo/mcp"
BODY = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}'
IAT = 1767225600  # 2026-01-01T00:00:00Z
JTI = "AAECAwQFBgcICQoLDA0ODw"

EXPECTED_ATH = "eaVdc24MF5rbKpTXWDI5W-tXHNfA1-qvFjwQ4GIhjlI"
EXPECTED_BH = "qXDbbSbAIAqtTp_paFTD5GK3FpDPUyMfdw3M-BeWpWw"
EXPECTED_BH_EMPTY = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
EXPECTED_PAYLOAD = (
    '{"ath":"eaVdc24MF5rbKpTXWDI5W-tXHNfA1-qvFjwQ4GIhjlI",'
    '"bh":"qXDbbSbAIAqtTp_paFTD5GK3FpDPUyMfdw3M-BeWpWw","htm":"POST",'
    '"htu":"/servers/demo/mcp","iat":1767225600,"jti":"AAECAwQFBgcICQoLDA0ODw"}'
)
# base64url(payload) "." base64url(signature).
EXPECTED_PROOF = (
    "eyJhdGgiOiJlYVZkYzI0TUY1cmJLcFRYV0RJNVctdFhITmZBMS1xdkZqd1E0R0loamxJIiwiYmgiOiJxWERiYlNiQ"
    "UlBcXRUcF9wYUZURDVHSzNGcERQVXlNZmR3M00tQmVXcFd3IiwiaHRtIjoiUE9TVCIsImh0dSI6Ii9zZXJ2ZXJzL2"
    "RlbW8vbWNwIiwiaWF0IjoxNzY3MjI1NjAwLCJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3In0"
    ".xDlJ_BHqkqNCj1L4e4RqJsHSO_DE71uRiqALR6CRFdMSC-ICPY8rojK3uyy_coSbhDFQBT1mpL0ECFk8sIlpBw"
)
# The same payload signed under the capability holder context.
EXPECTED_HOLDER_PROOF = (
    "eyJhdGgiOiJlYVZkYzI0TUY1cmJLcFRYV0RJNVctdFhITmZBMS1xdkZqd1E0R0loamxJIiwiYmgiOiJxWERiYlNiQ"
    "UlBcXRUcF9wYUZURDVHSzNGcERQVXlNZmR3M00tQmVXcFd3IiwiaHRtIjoiUE9TVCIsImh0dSI6Ii9zZXJ2ZXJzL2"
    "RlbW8vbWNwIiwiaWF0IjoxNzY3MjI1NjAwLCJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3In0"
    ".y-dA1G8M220lQyMubM0EyB8V2qAfznj-PA2WWHMYvmmgye7iNT60q4xXJW73e5hux4niRagPGEYNDYz7HQ5DAw"
)
# The signing input the proof covers, as hex: 8-byte length || context label || payload.
EXPECTED_PROOF_INPUT = (
    "000000000000001773616e61642f696e7374616e63652d70726f6f662f76327b22617468223a2265615664633234"
    "4d463572624b70545857444935572d7458484e6641312d7176466a7751344749686a6c49222c226268223a227158"
    "4462625362414941717454705f706146544435474b334670445055794d666477334d2d426557705777222c226874"
    "6d223a22504f5354222c22687475223a222f736572766572732f64656d6f2f6d6370222c22696174223a31373637"
    "3232353630302c226a7469223a2241414543417751464267634943516f4c4441304f4477227d"
)


def vector_kwargs(**overrides):
    """The vector's proof inputs, with iat and jti pinned."""
    kwargs = dict(
        method=METHOD, target=TARGET, principal_token=PRINCIPAL_TOKEN,
        body=BODY, iat=IAT, jti=JTI,
    )
    kwargs.update(overrides)
    return kwargs


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

    def test_proof_claim_vectors(self):
        b = proof_binding(**vector_kwargs())
        self.assertEqual(b["ath"], EXPECTED_ATH)
        self.assertEqual(b["bh"], EXPECTED_BH)
        # A request with no body still commits to one: the hash of zero bytes.
        self.assertEqual(proof_binding(**vector_kwargs(body=None))["bh"], EXPECTED_BH_EMPTY)

    def test_proof_payload_vector(self):
        got = proof_payload(proof_binding(**vector_kwargs())).decode("utf-8")
        print("proof payload =", got)
        self.assertEqual(got, EXPECTED_PAYLOAD)

    def test_proof_target(self):
        self.assertEqual(proof_target("https://gw.example.com/servers/demo/mcp"), "/servers/demo/mcp")
        self.assertEqual(proof_target("/servers/demo/mcp?cursor=abc"), "/servers/demo/mcp?cursor=abc")
        # Percent-encoding is preserved, not decoded into a real separator.
        self.assertEqual(proof_target("/servers/demo/a%2Fb"), "/servers/demo/a%2Fb")

    def test_proof_signing_input_vector(self):
        payload = proof_payload(proof_binding(**vector_kwargs()))
        got = sigctx_message(CTX_INSTANCE_PROOF, payload)
        print("proof signing input =", got.hex())
        self.assertEqual(got.hex(), EXPECTED_PROOF_INPUT)

    def test_proof_vector(self):
        got = proof(SEED_B64, **vector_kwargs())
        print("proof =", got)
        self.assertEqual(got, EXPECTED_PROOF)

    def test_capability_holder_proof_vector(self):
        got = capability_holder_proof(SEED_B64, **vector_kwargs())
        self.assertEqual(got, EXPECTED_HOLDER_PROOF)
        # Same payload, different signature: an instance proof must not pass as a holder proof.
        self.assertEqual(got.split(".")[0], EXPECTED_PROOF.split(".")[0])
        self.assertNotEqual(got.split(".")[1], EXPECTED_PROOF.split(".")[1])

    def test_proof_is_bound_to_the_request(self):
        base = proof(SEED_B64, **vector_kwargs())
        for override in [
            {"method": "GET"},
            {"target": "/servers/other/mcp"},
            {"target": TARGET + "?x=1"},
            {"principal_token": "another-token"},
            {"body": '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'},
            {"body": None},
            {"iat": IAT + 1},
            {"jti": "a-different-jti"},
        ]:
            self.assertNotEqual(proof(SEED_B64, **vector_kwargs(**override)), base, override)

    def test_two_proofs_for_one_request_differ(self):
        # A repeatable proof is a bearer token: whoever copies it is the instance.
        kwargs = dict(method=METHOD, target=TARGET, principal_token=PRINCIPAL_TOKEN, body=BODY)
        self.assertNotEqual(proof(SEED_B64, **kwargs), proof(SEED_B64, **kwargs))

    def test_proof_is_domain_separated_not_over_the_bare_token(self):
        from sanad import _b64url_encode, _load_private

        priv = _load_private(SEED_B64)
        # The pre-binding form: a signature over the token bytes. Ed25519 is deterministic,
        # so that value was identical on every request for the token's lifetime — a bearer
        # token with extra steps. The gateway rejects it.
        bare = _b64url_encode(priv.sign(PRINCIPAL_TOKEN.encode("utf-8")))
        self.assertNotEqual(proof(SEED_B64, **vector_kwargs()), bare)

        payload = proof_payload(proof_binding(**vector_kwargs()))
        tagged = _b64url_encode(priv.sign(sigctx_message(CTX_INSTANCE_PROOF, payload)))
        self.assertEqual(
            proof(SEED_B64, **vector_kwargs()), _b64url_encode(payload) + "." + tagged
        )
        # And the holder-proof context produces a different signature over those same bytes.
        holder = _b64url_encode(priv.sign(sigctx_message(CTX_CAPABILITY_HOLDER_PROOF, payload)))
        self.assertNotEqual(holder, tagged)

    def test_proof_same_for_seed_and_priv64(self):
        self.assertEqual(
            proof(SEED_B64, **vector_kwargs()),
            proof(PRIV64_B64, **vector_kwargs()),
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
        h = client.headers("demo", "/mcp", PRINCIPAL_TOKEN, method=METHOD, body=BODY)
        self.assertEqual(h["Authorization"], "Bearer " + PRINCIPAL_TOKEN)
        self.assertEqual(h[HEADER_CREDENTIAL], EXPECTED_CREDENTIAL_HEADER)
        # The proof is fresh per call, so the vector cannot be compared byte-for-byte; what
        # is pinned is that it is bound to THIS request.
        payload = json.loads(_b64url_decode(h[HEADER_PROOF].split(".")[0]))
        self.assertEqual(payload["htm"], METHOD)
        self.assertEqual(payload["htu"], TARGET)
        self.assertEqual(payload["ath"], EXPECTED_ATH)
        self.assertEqual(payload["bh"], EXPECTED_BH)
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
        h = client.headers("demo", "/mcp", PRINCIPAL_TOKEN)
        self.assertEqual(h[HEADER_DELEGATION], _b64url_encode(chain_text.encode("utf-8")))

    def test_credential_not_reserialized(self):
        # The header must be base64url of the exact bytes, not a re-serialized JSON.
        client = PassportClient(
            gateway_url="https://gw.example.com",
            instance_key=SEED_B64,
            credential=CREDENTIAL_TEXT,
        )
        h = client.headers("demo", "/mcp", PRINCIPAL_TOKEN)
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
        h = client.headers("demo", "/mcp", PRINCIPAL_TOKEN)
        # The proof carries a fresh jti, so what is asserted is the binding, not the bytes.
        payload = json.loads(_b64url_decode(h[HEADER_PROOF].split(".")[0]))
        self.assertEqual(payload["htm"], "GET")
        self.assertEqual(payload["htu"], "/servers/demo/mcp")
        self.assertEqual(payload["ath"], EXPECTED_ATH)
        self.assertEqual(payload["bh"], EXPECTED_BH_EMPTY)

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
