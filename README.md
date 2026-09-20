# algovoi-compliance-gate-a2a

The open, A2A-interoperable edition of the AlgoVoi **Compliance Gate**: a no-PII,
geo-bound, **seven-field Compliance Receipt** mapped to the A2A Payment Mandate and
Cart Mandate primitives. Apache-2.0.

This is deliberately the **receipt format and method**, not a screening engine. Your
operator supplies the categorical verdict (`ALLOW` / `REFER` / `DENY`) from whichever
screener you already run; this library canonicalises it into a recomputable,
content-addressed Compliance Receipt and binds it to A2A/AP2 mandates by reference.

Published as an open reference (offered to the A2A ecosystem, `a2aproject/A2A#1887`).
Provider-neutral by design: the screening provider names itself in
`screen_provider_did`, and geo resolution is a pluggable `GeoProvider`
(MaxMind GeoLite2 / IP2Location in production, an in-memory table for offline tests).

## The seven-field Compliance Receipt

```
canon_version, geo_ref, jurisdiction_flags, payer_ref,
screen_provider_did, screen_result, screen_timestamp_ms
```

Every reference is `"sha256:" + SHA-256(JCS(RFC 8785)(fields))` — the same
canonicalization A2A already mandates for Agent Card signing (spec section 8.4.1), so
the receipt shares A2A's existing byte discipline rather than introducing a new one.
The distinctive field is `geo_ref`: a first-class, content-addressed geo determination
(resolved country + ASN + provenance), so a verifier sees which jurisdiction a decision
was made against. **No raw IP or address is ever recorded.**

The Python and Node (`@algovoi/compliance-gate-a2a`) reference implementations produce
byte-identical receipts (same `receipt_ref`) on a clean box.

## Install

```bash
pip install algovoi-compliance-gate-a2a
```

## Usage

```python
from algovoi_compliance_gate_a2a import (
    InMemoryGeoProvider, resolve_geo_ref, payer_ref,
    compliance_receipt, receipt_ref, to_a2a_extension,
)

# Geo resolution is pluggable; production injects a MaxMind/IP2Location provider.
geo = InMemoryGeoProvider([{"cidr": "203.0.113.0/24", "country": "GB", "asn": 64500}])
det, gref = resolve_geo_ref(
    geo, ip="203.0.113.7",
    geo_source_did="did:web:algovoi.co.uk", resolved_at_ms=1719412800000,
)  # the IP is used only to resolve country/ASN, then discarded

receipt = compliance_receipt(
    payer_ref=payer_ref("eip155:8453", "0xabc..."),
    screen_result="ALLOW",                              # your operator supplies this
    screen_provider_did="did:web:your-screener.example",# your provider names itself
    screen_timestamp_ms=1719412800000,
    jurisdiction_flags=["ofac", "eu"],                  # ordered screening scope
    geo_ref=gref,
)

# receipt_ref recomputes from the receipt alone, byte-identical in Node.
print(receipt_ref(receipt))  # -> "sha256:..."

# Bind to AP2 mandates by their own handles, emitted under AlgoVoi's A2A extension URI.
ext = to_a2a_extension(receipt=receipt, payment_mandate_id="pm_123",
                       cart_hash="sha256:...")
```

Verify anywhere, with no issuer contact:

```python
from algovoi_compliance_gate_a2a import verify_receipt_ref
assert verify_receipt_ref(receipt, receipt_ref(receipt))
```

## What this is and is not

- **Is:** an Apache-2.0 receipt format + A2A/AP2 binding + a pluggable geo determination.
- **Is not:** a sanctions/AML screening engine. You supply `screen_result`; this library
  never decides `ALLOW` / `REFER` / `DENY` for you (the one exception is
  `jurisdiction_decision`, which is geo-policy logic over a country you already resolved,
  not screening).

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
