# Algovoi-compliance-gate-a2a


[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

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

Every reference is `"sha256:" + SHA-256(JCS(RFC 8785)(fields))`, the same
canonicalization A2A already mandates for Agent Card signing (spec section 8.4.1), so
the receipt shares A2A's existing byte discipline rather than introducing a new one.
The distinctive field is `geo_ref`: a first-class, content-addressed geo determination
(resolved country + ASN + provenance), so a verifier sees which jurisdiction a decision
was made against. **No raw IP or address is ever recorded.**

The Python and Node (`@algovoi/compliance-gate-a2a`) reference implementations produce
byte-identical receipts (same `receipt_ref`) on a clean box.

## Install

This is published as source (Apache-2.0), not to PyPI. Install directly from the repo:

```bash
pip install "git+https://github.com/chopmob-cloud/algovoi-compliance-gate-a2a.git#subdirectory=python"
```

Or clone and install locally:

```bash
git clone https://github.com/chopmob-cloud/algovoi-compliance-gate-a2a.git
pip install ./algovoi-compliance-gate-a2a/python
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

## Wiring into a Keystone decision

The receipt binds into a Keystone-style decision **by reference** and is never mutated.
The `receipt_ref` is the `screen_ref`, and a decision layer binds to the screen that
preceded it:

```
screen_ref         = receipt_ref(receipt)
screen_binding_ref = "sha256:" + SHA-256(JCS({decision_ref, screen_ref}))
```

`screen_binding_ref` recomputes offline from the two references alone, so a verifier can
prove a decision ran against *this* screen with no issuer contact (consistency, not
correlation). Fold that reference into your decision audit next to its passport, mandate,
and policy references; leaving it out is byte-identical to the no-compliance path (it is
purely additive). A runnable end-to-end example is in
[`examples/keystone_binding.py`](examples/keystone_binding.py):

```bash
PYTHONPATH=python python examples/keystone_binding.py
```

The commercial AlgoVoi Keystone additionally proves *which* decision standard drove the
verdict and post-quantum signs the whole evidence chain; that layer is out of scope for
this open edition, which supplies the receipt and the reference that binds it.

## The x402 payment-rail format (`x402_rail`)

The same repo also ships the open **x402 pay-rail format and method** the AlgoVoi rail
speaks at `pay.algovoi.co.uk`: how to construct a spec-correct, multi-lane **x402 v2 `402`
challenge**, the **MPP `application/problem+json` (RFC 9457)** payment-required body, and the
rail's **discovery** surfaces. Like the Compliance Receipt, it is the *format*, not the engine:
it builds the advertised payment terms, holds no keys, signs nothing on-chain, and settles
nothing. The operator supplies the payout address per lane.

It captures four correctness lessons the rail learned in production, each a pure recomputable
transform:

1. **Per-lane native decimals.** USDC is not 6-decimal everywhere, Stellar USDC is 7-decimal.
   The advertised `extra.decimals` must match the scale of `maxAmountRequired`, or a client
   reads a 10x-wrong price. `native_amount` rescales and a guard proves they agree.
2. **MPP over RFC 9457.** The MPP payment-required body is `application/problem+json`,
   `status: 402`, with an `accepts` member.
3. **Dash-clean output.** Advertised strings carry no em/en dashes; `assert_ascii_dashes_only`
   rejects them.
4. **Multi-lane, multi-face discovery.** One `accepts[]` entry per enabled lane; the discovery
   entry names the faces (`x402` / `mpp` / `ap2` / `a2a`) a rail speaks.

```python
from algovoi_compliance_gate_a2a.x402_rail import (
    build_accept, build_x402_challenge, build_mpp_problem, challenge_ref,
)

# 0.01 USDC, priced once in canonical 6-decimal microUSDC; each lane rescales.
base = build_accept(network="eip155:8453", asset="0x8335...2913", pay_to="0xYOUR_PAYOUT",
                    resource="https://pay.example/verify/receipt", price_micro=10000,
                    decimals=6, scheme_kind="eip3009-exact",
                    description="pay 0.01 USDC on Base")
stellar = build_accept(network="stellar:pubnet", asset="USDC:GA5Z...", pay_to="GYOUR_PAYOUT",
                       resource="https://pay.example/verify/receipt", price_micro=10000,
                       decimals=7, scheme_kind="avm-note",   # 7-decimal -> amount 100000
                       description="pay 0.01 USDC on Stellar")

challenge = build_x402_challenge([base, stellar], error="Payment required")
print(challenge_ref(challenge))              # "sha256:..." recomputable, byte-identical in Node
```

The Node build is byte-identical (`@algovoi/compliance-gate-a2a/x402-rail`,
`buildAccept` / `buildX402Challenge` / `challengeRef`). A runnable example is in
[`examples/x402_rail_402.py`](examples/x402_rail_402.py):

```bash
PYTHONPATH=python python examples/x402_rail_402.py
```

Byte-parity is pinned in [`tests/test_x402_rail_parity.py`](tests/test_x402_rail_parity.py)
and [`tests/x402Rail.parity.mjs`](tests/x402Rail.parity.mjs) (a fixed Base + Stellar challenge
must produce the same `challenge_ref` in both languages). This is the interoperability surface
only; verification and on-chain settlement stay in the commercial rail and are out of scope here.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
