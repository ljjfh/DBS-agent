"""Verify a downloaded payment receipt OFFLINE - no server, no model, no network.

    python scripts/verify_receipt.py ~/Downloads/receipt-TXN-XXXX.json

Checks the whole chain:
  1. the card on the receipt hashes to the digest                     (what was shown)
  2. the signed payload carries that same digest, payee and amount    (what was signed)
  3. the signature is valid for the device's public key               (who signed)
     - passkey receipts: the device also confirmed the fingerprint / face check (WebAuthn UV flag) and the
       passkey's challenge is SHA-256 of the exact signed payload
  4. the receipt itself hasn't been edited                            (receipt_sha256)

It proves the payment matches what this device key signed. It does NOT prove a real bank identity - in this
prototype the key is registered by the browser session, not bound to a verified customer.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.kernel import p256, webauthn  # noqa: E402
from app.kernel.signing import canonical, verify_device_signature  # noqa: E402


def check(receipt: dict) -> list[tuple[str, bool]]:
    out = []
    body = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
    out.append(("Receipt not edited", hashlib.sha256(canonical(body).encode()).hexdigest() == receipt.get("receipt_sha256")))
    card, digest = receipt["card"], receipt["digest"]
    out.append(("Card matches its digest", hashlib.sha256(canonical(card).encode()).hexdigest() == digest))
    auth = receipt.get("authorization", {})
    if "payload" not in auth:
        out.append(("Signed by a device key", False))
        return out
    signed = json.loads(auth["payload"])
    out.append(("Signed payload is for this exact card",
                signed["digest"] == digest and signed["amount_cents"] == card["amount_cents"]
                and signed["payee"] == card["payee_name"] and signed["draft_id"] == card["draft_id"]))
    if auth.get("method") == "passkey":
        try:
            cd = json.loads(webauthn.unb64u(auth["client_data_json"]))
            webauthn.verify_assertion(public_key=auth["public_key"], payload=auth["payload"],
                                      authenticator_data=auth["authenticator_data"],
                                      client_data_json=auth["client_data_json"], signature=auth["signature"],
                                      rp_id=auth["rp_id"], origins={cd.get("origin")})
            ok = True
        except webauthn.WebAuthnError:
            ok = False
        out.append(("Passkey signature valid, fingerprint/face checked on the device", ok))
    else:
        out.append(("Signature valid for the device key", verify_device_signature(auth["public_key"], auth["payload"],
                                                                                 auth["signature"])))
    out.append((f"Key id {webauthn.key_id(auth['public_key'])} matches",
                webauthn.key_id(auth["public_key"]) == auth.get("key_id")))
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    receipt = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    results = check(receipt)
    card = receipt["card"]
    print(f"Receipt {receipt['txn_id']}: S${card['amount_cents'] / 100:,.2f} to {card['payee_name']}")
    for name, ok in results:
        print(f"  {'✓' if ok else '✗'} {name}")
    ok = all(ok for _, ok in results)
    print("VALID" if ok else "INVALID")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
