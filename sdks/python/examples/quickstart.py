"""Sanad Python SDK — quickstart.

Flow: generate an instance key -> enroll to get a workload credential -> make an
authenticated request through the gateway. This mirrors the Go `passport proxy`
sidecar: the SDK injects the principal token, the workload credential, a proof of
possession, and (optionally) a delegation chain onto every request.

Run:
    AUTHORITY_URL=... GATEWAY_URL=... BOOTSTRAP_TOKEN=... PRINCIPAL_TOKEN=... \
        python examples/quickstart.py
"""

import os

from sanad import PassportClient, enroll, generate_instance_key


def main() -> None:
    authority_url = os.environ.get("AUTHORITY_URL", "https://authority.example.com")
    gateway_url = os.environ.get("GATEWAY_URL", "https://gw.example.com")
    bootstrap_token = os.environ.get("BOOTSTRAP_TOKEN", "dev-bootstrap-token")
    principal_token = os.environ.get("PRINCIPAL_TOKEN", "dev-principal-token")
    # In VC mode the principal token is a credential, not a bearer token: the gateway also
    # wants a per-request proof of possession of the subject's did:key. Unset in OIDC mode.
    principal_key = os.environ.get("PRINCIPAL_KEY") or None
    server_id = os.environ.get("SERVER_ID", "example-server")

    # 1) Generate an Ed25519 instance key. The private_key is interchangeable with
    #    the Go CLI's `passport keygen` key file (base64url of seed(32)||pub(32)).
    key = generate_instance_key()
    print("public key:", key["public_key"])

    # Persist the private key if you want to reuse the same instance identity:
    #   with open("agent.key", "w") as f:
    #       f.write(key["private_key"])

    # 2) Enroll: present the bootstrap token + public key, receive a short-lived
    #    workload credential. The raw credential text is kept verbatim.
    if os.environ.get("RUN_NETWORK") == "1":
        result = enroll(authority_url, bootstrap_token, key["public_key"])
        print("enrolled as:", result["agent_id"], "expires:", result["not_after"])
        credential = result["credential"]

        # 3) Build a client and make an authenticated request through the gateway.
        client = PassportClient(
            gateway_url, key["private_key"], credential, principal_key=principal_key
        )
        resp = client.request(
            server_id,
            "/mcp",
            principal_token=principal_token,
            method="POST",
            body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
            headers={"Content-Type": "application/json"},
        )
        print("status:", resp.status)
        print("body:", resp.text())
    else:
        print("Set RUN_NETWORK=1 (plus AUTHORITY_URL/GATEWAY_URL/tokens) to enroll and call the gateway.")


if __name__ == "__main__":
    main()
