"""Sanad Python client SDK.

This SDK lets an AI agent authenticate to the Sanad gateway. It mirrors
the Go sidecar ``passport proxy`` (see ``cmd/passport``): first the agent enrolls
to obtain a short-lived workload credential, then it attaches the correct headers
to each MCP request routed through the gateway.

Wire formats match the Go implementation byte-for-byte. All base64 is RFC 4648
URL-safe with NO padding (Go's ``base64.RawURLEncoding``). Cryptography is
Ed25519.

Every signature is domain-separated: it is made over
``uint64be(len(ctx)) || ctx || message``, where ``ctx`` names what is being signed
(see :func:`sigctx_message`). Signing the bare message is not accepted by the gateway.

The proof of possession is bound to ONE request. It is the DPoP construction (RFC 9449)
in Sanad's signature format: a payload naming the method (``htm``), the target (``htu``),
a hash of the principal token (``ath``), a hash of the body (``bh``), a creation time
(``iat``) and a unique id (``jti``), signed under the instance-proof context. See
:func:`proof` for why the body is covered when DPoP leaves it out. A proof therefore
cannot be computed once and reused — that is the point, and a client that caches one is
denied on its second request.

A gateway in VC mode expects TWO proofs on each request: one from the agent instance
(``X-Agent-Proof``) and one from the principal whose credential is being presented
(``X-Principal-Proof``). A principal credential is not a bearer token — see
:func:`principal_holder_proof` and the ``principal_key`` client argument.

Enrolling is two requests: the agent fetches a single-use nonce from the authority,
then presents attestation evidence that covers both that nonce and the public key it
is enrolling. That binding is what stops an enrollment captured off the wire from
being replayed with somebody else's key.

Typical use::

    from sanad import generate_instance_key, enroll, PassportClient

    key = generate_instance_key()
    result = enroll("https://authority.example.com", "bootstrap-token", key["public_key"])
    client = PassportClient("https://gw.example.com", key["private_key"], result["credential"])
    resp = client.request("my-server", "/mcp", principal_token="<opaque principal token>")
    print(resp.status, resp.body)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

__all__ = [
    "generate_instance_key",
    "public_key_of",
    "proof",
    "capability_holder_proof",
    "principal_holder_proof",
    "request_proof",
    "proof_binding",
    "proof_payload",
    "proof_target",
    "sigctx_message",
    "CTX_INSTANCE_PROOF",
    "CTX_CAPABILITY_HOLDER_PROOF",
    "CTX_VC_HOLDER_PROOF",
    "bootstrap_evidence",
    "request_nonce",
    "enroll",
    "PassportClient",
    "Response",
    "PassportError",
    "EnrollmentError",
    "HEADER_CREDENTIAL",
    "HEADER_PROOF",
    "HEADER_DELEGATION",
    "HEADER_PRINCIPAL_PROOF",
]

# Header names must match the Go constants exactly.
HEADER_CREDENTIAL = "X-Agent-Credential"        # workload/workload.go: HeaderCredential
HEADER_PROOF = "X-Agent-Proof"                  # workload/workload.go: HeaderProof
HEADER_DELEGATION = "X-Agent-Delegation"        # delegation/transport.go: HeaderDelegation
HEADER_PRINCIPAL_PROOF = "X-Principal-Proof"    # vc/holder.go: HeaderPrincipalProof

_SEED_SIZE = 32
_PUB_SIZE = 32
_PRIV64_SIZE = 64  # seed(32) || public(32), matching Go's ed25519.PrivateKey

# Context label for an instance proof of possession (Go's ``sigctx.InstanceProof``).
#
# ``v2`` because the proof changed meaning: ``v1`` signed the bare principal token, ``v2``
# signs a request binding. The label moved so a ``v1`` proof cannot be replayed against the
# new semantics — it now verifies under no context at all.
CTX_INSTANCE_PROOF = "sanad/instance-proof/v2"

# Context label for a capability holder proof (Go's ``sigctx.CapabilityHolderProof``). The
# payload is the same shape as an instance proof; only the label differs, and that is what
# stops one from being presented as the other when both are signed by keys that can coincide.
CTX_CAPABILITY_HOLDER_PROOF = "sanad/capability-holder-proof/v2"

# Context label for a principal holder proof (Go's ``sigctx.VCHolderProof``): the presenter of
# a W3C-style principal credential proving possession of the credential subject's ``did:key``
# private key. Again the same payload shape, and again the label is the only thing keeping one
# kind of signature from being read as another — a principal's ``did:key`` also signs
# delegation hops and, if it is an issuer, credentials.
CTX_VC_HOLDER_PROOF = "sanad/vc-holder-proof/v1"


class PassportError(Exception):
    """Base class for SDK errors."""


class EnrollmentError(PassportError):
    """Raised when enrollment returns a non-200 status."""

    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"enroll: HTTP {status}: {body.strip()}")


# --- base64url (RFC 4648, no padding) helpers -----------------------------------

def _b64url_encode(b: bytes) -> str:
    """Encode raw bytes as unpadded URL-safe base64 (Go base64.RawURLEncoding)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Decode unpadded URL-safe base64, re-adding padding first."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# --- Ed25519 key helpers --------------------------------------------------------

def _load_private(private_key: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a base64url string.

    Accepts either a 32-byte seed or the 64-byte ``seed || public`` form (as the
    Go CLI persists it). The first 32 bytes are used as the seed.
    """
    raw = _b64url_decode(private_key)
    if len(raw) not in (_SEED_SIZE, _PRIV64_SIZE):
        raise PassportError(
            f"instance private key must be {_SEED_SIZE} or {_PRIV64_SIZE} bytes, got {len(raw)}"
        )
    seed = raw[:_SEED_SIZE]
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_raw(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# --- Public key/proof primitives ------------------------------------------------

def generate_instance_key() -> Dict[str, str]:
    """Generate a fresh Ed25519 instance key.

    Returns a dict with:

    - ``private_key``: base64url of the 64-byte ``seed(32) || public(32)`` form,
      interchangeable with the Go ``passport keygen`` key file.
    - ``public_key``: base64url of the 32-byte raw public key.
    """
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw() if hasattr(priv, "private_bytes_raw") else _seed_of(priv)
    pub = _public_raw(priv)
    return {
        "private_key": _b64url_encode(seed + pub),
        "public_key": _b64url_encode(pub),
    }


def _seed_of(priv: Ed25519PrivateKey) -> bytes:
    """Extract the 32-byte seed for cryptography versions lacking private_bytes_raw."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def public_key_of(private_key: str) -> str:
    """Return the base64url public key for a base64url private key (seed or seed||pub)."""
    return _b64url_encode(_public_raw(_load_private(private_key)))


def sigctx_message(ctx: str, message: bytes) -> bytes:
    """Build the domain-separated signing input Go's ``sigctx.Message`` produces.

    ``uint64be(len(ctx)) || utf8(ctx) || message``.

    The 8-byte big-endian length prefix is what makes the encoding unambiguous: it fixes
    exactly where the label ends, so the bytes parse back to one ``(ctx, message)`` pair
    and no label can be read as the head of a message. The instance key signs more than
    one kind of thing (it proves possession here, and authenticates the delegation hops
    the agent signs), and the label is what keeps a signature made for one from being
    accepted as the other.
    """
    label = ctx.encode("utf-8")
    return len(label).to_bytes(8, "big") + label + message


# --- Request-bound proof of possession (DPoP, RFC 9449) -------------------------

def _sha256_b64(data: bytes) -> str:
    """base64url(SHA-256(data)) — the digest form both ``ath`` and ``bh`` use."""
    return _b64url_encode(hashlib.sha256(data).digest())


def proof_target(url: str) -> str:
    """Return the ``htu`` value for a URL: the origin-form target the gateway will see.

    Mirrors Go's ``pop.Target``. Accepts an absolute URL or a bare path.

    The authority is deliberately absent: the gateway sits behind TLS terminators,
    ingresses and the ``passport proxy`` sidecar, any of which can rewrite the scheme or
    the Host header, so binding a value the two ends compute differently buys an outage
    rather than security. The query IS included, where RFC 9449 drops it — nothing between
    an agent and the gateway rewrites query strings, and covering it is strictly stronger.
    """
    parts = urllib.parse.urlsplit(url)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    return target


def proof_binding(
    method: str,
    target: str,
    principal_token: str,
    body: Optional[Union[bytes, str]] = None,
    iat: Optional[int] = None,
    jti: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the claim set a proof commits to. Mirrors Go's ``pop.NewBinding``.

    ``iat`` and ``jti`` default to now and to 128 fresh random bits (above the 96 RFC 9449
    §4.2 asks for); pass them only for tests and pinned vectors.
    """
    if body is None:
        raw = b""
    elif isinstance(body, str):
        raw = body.encode("utf-8")
    else:
        raw = body
    return {
        "ath": _sha256_b64(principal_token.encode("utf-8")),
        "bh": _sha256_b64(raw),
        "htm": method,
        "htu": target,
        "iat": int(time.time()) if iat is None else iat,
        "jti": _b64url_encode(os.urandom(16)) if jti is None else jti,
    }


def proof_payload(binding: Dict[str, Any]) -> bytes:
    """Serialize a binding to the canonical payload bytes.

    Compact JSON with the keys in the order above, and ``ensure_ascii=False`` so the output
    matches Go's ``pop.Encode`` (an encoder with HTML escaping off) and JavaScript's
    ``JSON.stringify`` byte-for-byte.
    """
    ordered = {k: binding[k] for k in ("ath", "bh", "htm", "htu", "iat", "jti")}
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def request_proof(
    ctx: str,
    private_key: str,
    method: str,
    target: str,
    principal_token: str,
    body: Optional[Union[bytes, str]] = None,
    iat: Optional[int] = None,
    jti: Optional[str] = None,
) -> str:
    """Sign a request binding under ``ctx``, returning ``base64url(payload).base64url(sig)``.

    Mirrors Go's ``pop.Sign``. The signature covers the payload bytes as transmitted, so the
    gateway never re-encodes what it is checking and the three SDK languages cannot disagree
    about JSON details.
    """
    priv = _load_private(private_key)
    payload = proof_payload(proof_binding(method, target, principal_token, body, iat, jti))
    sig = priv.sign(sigctx_message(ctx, payload))
    return _b64url_encode(payload) + "." + _b64url_encode(sig)


def proof(
    private_key: str,
    method: str,
    target: str,
    principal_token: str,
    body: Optional[Union[bytes, str]] = None,
    iat: Optional[int] = None,
    jti: Optional[str] = None,
) -> str:
    """Produce the ``X-Agent-Proof`` value for ONE request. Mirrors ``workload.Proof``.

    The proof commits to the method, the target, a hash of the principal token (``ath``) and
    a hash of the body (``bh``), plus a creation time and a unique id. The gateway checks
    each against the request in front of it, requires the proof to be seconds old, and spends
    the ``jti`` on first use.

    Two departures from RFC 9449 are worth knowing about. The serialization is not a JWT: the
    key is already carried in a CA-signed workload credential, so DPoP's ``jwk`` header would
    be strictly weaker, and a parsed ``alg`` field is the root of the whole JWT confusion
    family. And the body IS covered, which RFC 9449 §11.7 explicitly does not do: in MCP
    streamable HTTP every JSON-RPC message is POSTed to one endpoint, so method and path are
    identical for ``tools/list`` and for a ``tools/call`` of any tool — a proof that stopped
    at the URL would leave a captured header bundle usable to invoke anything.

    Do NOT cache the result. Computing it once and reusing it is precisely the bug this
    construction fixes, and the gateway rejects the second request.
    """
    return request_proof(
        CTX_INSTANCE_PROOF, private_key, method, target, principal_token, body, iat, jti
    )


def capability_holder_proof(
    holder_secret: str,
    method: str,
    target: str,
    principal_token: str,
    body: Optional[Union[bytes, str]] = None,
    iat: Optional[int] = None,
    jti: Optional[str] = None,
) -> str:
    """Produce the ``X-Agent-Capability-Proof`` value for one request.

    The same binding as :func:`proof`, signed under the capability holder context. Mirrors
    Go's ``delegation.HolderProof``.
    """
    return request_proof(
        CTX_CAPABILITY_HOLDER_PROOF, holder_secret, method, target, principal_token, body, iat, jti
    )


def principal_holder_proof(
    principal_key: str,
    method: str,
    target: str,
    principal_token: str,
    body: Optional[Union[bytes, str]] = None,
    iat: Optional[int] = None,
    jti: Optional[str] = None,
) -> str:
    """Produce the ``X-Principal-Proof`` value for one request. Mirrors Go's ``vc.HolderProof``.

    A gateway in VC mode (``PASSPORT_PRINCIPAL_MODE=vc``) does not treat the principal
    credential as a bearer token: the credential proves that a trusted issuer vouched for a
    ``did:key``, and this proves that the caller actually holds that key, on this request.
    Both are required. Without it the credential would be exactly as good as a copy of it,
    which is what anything that sees one request's headers gets for free.

    :param principal_key: base64url ``did:key`` private key of the credential SUBJECT — not
        the instance key, and not the issuer's key.
    :param principal_token: the credential string exactly as sent in the Authorization
        header, since the proof commits to it (``ath``).
    """
    return request_proof(
        CTX_VC_HOLDER_PROOF, principal_key, method, target, principal_token, body, iat, jti
    )


# --- Enrollment -----------------------------------------------------------------

def bootstrap_evidence(bootstrap_token: str, nonce: bytes, public_key: bytes) -> bytes:
    """Build the attestation evidence a Go ``workload.TokenAttestor`` accepts.

    An HMAC-SHA256, keyed by the bootstrap token, over the authority-issued nonce and
    the public key being enrolled. Mirrors Go's ``workload.BootstrapEvidence``
    byte-for-byte: the MAC input is the canonical JSON Go signs over, with the fields
    in that order and the byte fields in standard (padded) base64, which is how Go's
    ``encoding/json`` renders ``[]byte``.

    The bootstrap token never leaves the process, and the result only enrolls this key
    against this nonce — so an enrollment captured off the wire cannot be replayed with
    somebody else's key.
    """
    msg = json.dumps(
        {
            "ctx": "sanad/bootstrap-evidence/v1",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "pub": base64.b64encode(public_key).decode("ascii"),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(bootstrap_token.encode("utf-8"), msg, hashlib.sha256).digest()


def _post_json(url: str, payload: Dict[str, Any]) -> str:
    """POST a JSON body and return the response text, raising EnrollmentError on failure."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode("utf-8")
            status = resp.getcode()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise EnrollmentError(e.code, body) from None

    if status != 200:
        raise EnrollmentError(status, raw)
    return raw


def request_nonce(authority_url: str) -> bytes:
    """Fetch a single-use enrollment nonce from ``POST {authority_url}/enroll/nonce``.

    Mirrors Go's ``workload.RequestNonce``. The nonce is the RATS freshness challenge
    (carried as EAT ``eat_nonce``): the authority accepts it exactly once, within a
    short window, so an attestation built over it cannot be replayed.

    :raises EnrollmentError: on a non-200 response or an unusable nonce.
    """
    raw = _post_json(authority_url.rstrip("/") + "/enroll/nonce", {})
    nonce = json.loads(raw).get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise EnrollmentError(200, "authority returned an unusable nonce")
    return _b64url_decode(nonce)


def enroll(authority_url: str, bootstrap_token: str, public_key: str) -> Dict[str, Any]:
    """Enroll with the authority and return the issued workload credential.

    Mirrors Go's ``workload.Enroll``, which is two requests:

    1. ``POST {authority_url}/enroll/nonce`` for a single-use challenge, then
    2. ``POST {authority_url}/enroll`` with ``{"nonce": ..., "evidence": ...,
       "public_key": ...}``, where the evidence covers both the nonce and the public
       key (see :func:`bootstrap_evidence`).

    On HTTP 200 the response body is the credential JSON, kept verbatim (its embedded
    signature must not be re-serialized).

    Call this once, at startup, and persist the credential: a bootstrap token is
    single-use and expiring — it authorizes a bounded number of enrollments (one, by
    default) inside a bounded window. A 403 naming a spent or expired token is
    permanent and retrying cannot fix it; a 429 is the authority's enrollment rate
    limit and carries a ``Retry-After`` header to wait for.

    :param authority_url: base URL of the authority service.
    :param bootstrap_token: attestation bootstrap token (opaque string). Read it from a
        file or the environment, never a command-line argument — argv is readable by
        every process on the host.
    :param public_key: base64url of the 32-byte instance public key.
    :returns: ``{"credential": <raw text>, "agent_id": ..., "not_after": ...}``.
    :raises EnrollmentError: on a non-200 response.
    """
    pub = _b64url_decode(public_key)
    if len(pub) != _PUB_SIZE:
        raise PassportError(f"instance public key must be {_PUB_SIZE} bytes, got {len(pub)}")

    nonce = request_nonce(authority_url)
    raw = _post_json(
        authority_url.rstrip("/") + "/enroll",
        {
            "nonce": _b64url_encode(nonce),
            "evidence": _b64url_encode(bootstrap_evidence(bootstrap_token, nonce, pub)),
            "public_key": public_key,
        },
    )

    # Keep the credential text exactly as received; only parse for convenience fields.
    parsed = json.loads(raw)
    return {
        "credential": raw,
        "agent_id": parsed.get("AgentID"),
        "not_after": parsed.get("NotAfter"),
    }


# --- Client ---------------------------------------------------------------------

@dataclass
class Response:
    """A minimal HTTP response returned by :meth:`PassportClient.request`."""

    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def text(self, encoding: str = "utf-8") -> str:
        """Decode the response body as text."""
        return self.body.decode(encoding, errors="replace")

    def json(self) -> Any:
        """Parse the response body as JSON."""
        return json.loads(self.body.decode("utf-8"))


def _credential_text(credential: Union[str, Dict[str, Any]]) -> str:
    """Accept either the raw credential text or the dict returned by :func:`enroll`."""
    if isinstance(credential, dict):
        text = credential.get("credential")
        if not isinstance(text, str):
            raise PassportError("credential dict must contain a 'credential' text field")
        return text
    if isinstance(credential, str):
        return credential
    raise PassportError("credential must be a string or the dict returned by enroll()")


def _instance_key_str(instance_key: Union[str, Dict[str, Any]]) -> str:
    """Accept either the private key string or the dict from generate_instance_key()."""
    if isinstance(instance_key, dict):
        key = instance_key.get("private_key")
        if not isinstance(key, str):
            raise PassportError("instance_key dict must contain a 'private_key' field")
        return key
    if isinstance(instance_key, str):
        return instance_key
    raise PassportError("instance_key must be a string or the dict from generate_instance_key()")


class PassportClient:
    """Attaches Sanad headers and forwards MCP requests to the gateway.

    This mirrors the ``passport proxy`` sidecar: it injects the principal token,
    the workload credential, a proof of possession of the instance key, a proof of
    possession of the principal's ``did:key`` when one is configured, and (optionally)
    a delegation chain onto every request.

    :param gateway_url: base URL of the gateway.
    :param instance_key: base64url private key (seed or seed||pub), or the dict from
        :func:`generate_instance_key`.
    :param credential: the raw credential JSON text, or the dict from :func:`enroll`.
    :param delegation: optional delegation chain JSON text (a string), or ``None``.
    :param principal_key: the principal's base64url ``did:key`` private key. Required by
        gateways in VC mode, where the principal credential is not a bearer token and each
        request carries a proof of possession of this key (see
        :func:`principal_holder_proof`). Omit it in OIDC mode, where there is no such key.
    """

    def __init__(
        self,
        gateway_url: str,
        instance_key: Union[str, Dict[str, Any]],
        credential: Union[str, Dict[str, Any]],
        delegation: Optional[str] = None,
        principal_key: Optional[str] = None,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self._private_key = _instance_key_str(instance_key)
        # Validate the keys early.
        _load_private(self._private_key)
        self._credential_text = _credential_text(credential)
        self._delegation = delegation
        self._principal_key = principal_key
        if principal_key is not None:
            _load_private(principal_key)

    def url(self, server_id: str, path: str) -> str:
        """Build the full gateway URL: ``{gateway_url}/servers/{server_id}{path}``."""
        return f"{self.gateway_url}/servers/{server_id}{path}"

    def headers(
        self,
        server_id: str,
        path: str,
        principal_token: str,
        method: str = "GET",
        body: Optional[Union[bytes, str]] = None,
    ) -> Dict[str, str]:
        """Build the passport headers for ONE request.

        It takes the request — server, path, method and body — because the proof is bound to
        all of them. The returned headers are good for that request and no other; building
        them once and reusing them across calls is the bug this construction exists to fix.
        """
        target = proof_target(self.url(server_id, path))
        h = {
            "Authorization": "Bearer " + principal_token,
            HEADER_CREDENTIAL: _b64url_encode(self._credential_text.encode("utf-8")),
            HEADER_PROOF: proof(self._private_key, method, target, principal_token, body),
        }
        if self._principal_key is not None:
            h[HEADER_PRINCIPAL_PROOF] = principal_holder_proof(
                self._principal_key, method, target, principal_token, body
            )
        if self._delegation is not None:
            h[HEADER_DELEGATION] = _b64url_encode(self._delegation.encode("utf-8"))
        return h

    def request(
        self,
        server_id: str,
        path: str,
        principal_token: str,
        method: str = "GET",
        body: Optional[Union[bytes, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Response:
        """Send an authenticated request to ``/servers/{server_id}{path}`` on the gateway.

        :param server_id: id of the protected server registered at the gateway.
        :param path: upstream path, must begin with ``/``.
        :param principal_token: opaque principal bearer token.
        :param method: HTTP method (default ``GET``).
        :param body: request body as bytes or str (str is UTF-8 encoded).
        :param headers: extra headers merged after the passport headers.
        :returns: a :class:`Response`.
        """
        if not path.startswith("/"):
            raise PassportError("path must begin with '/'")

        url = self.url(server_id, path)

        data: Optional[bytes] = None
        if body is not None:
            data = body.encode("utf-8") if isinstance(body, str) else body

        # The proof commits to a hash of the bytes actually sent, so it is built from `data`
        # after encoding rather than from the caller's str/bytes union.
        all_headers = self.headers(server_id, path, principal_token, method=method, body=data)
        if headers:
            all_headers.update(headers)

        req = urllib.request.Request(url, data=data, method=method, headers=all_headers)
        try:
            with urllib.request.urlopen(req) as resp:
                return Response(
                    status=resp.getcode(),
                    headers=dict(resp.headers.items()),
                    body=resp.read(),
                )
        except urllib.error.HTTPError as e:
            # A non-2xx status is returned as a Response rather than raised.
            return Response(
                status=e.code,
                headers=dict(e.headers.items()) if e.headers else {},
                body=e.read(),
            )
