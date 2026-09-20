# Show & Tell: an open, no-PII Compliance Receipt for A2A / AP2 agent payments

We built an open, A2A-interoperable **Compliance Gate** receipt and we're releasing it
as a public Apache-2.0 reference. It is a goodwill contribution to the agent-payments
ecosystem: use it, fork it, extend it, or ignore it.

## What it is

A **seven-field Compliance Receipt** that turns a screening verdict into a recomputable,
no-PII, content-addressed object any party can verify with no issuer contact:

```
canon_version, geo_ref, jurisdiction_flags, payer_ref,
screen_provider_did, screen_result, screen_timestamp_ms
```

Every reference is `"sha256:" + SHA-256(JCS(RFC 8785)(fields))` — the **same
canonicalization A2A already mandates for Agent Card signing** (spec section 8.4.1), so
the receipt reuses A2A's byte discipline rather than inventing a new one. It binds to
AP2's mandate primitives by AP2's own handles (`payment_mandate_id`, `cart_hash`), and is
emitted as an A2A extension under our own URI namespace — never inside an A2A/AP2
controlled namespace.

## What makes it useful

- **No PII.** No raw IP or address is ever recorded — `geo_ref` binds only the resolved
  country + ASN plus provenance (resolver DID, method, timestamp).
- **Provider-neutral.** This is deliberately **not** a screening engine. Your operator
  supplies the categorical verdict (`ALLOW` / `REFER` / `DENY`) from whatever screener you
  already run, and that provider names itself in `screen_provider_did`. Geo resolution is a
  pluggable `GeoProvider` (MaxMind GeoLite2 / IP2Location in production).
- **Recomputable by anyone.** `receipt_ref` is derived from the receipt alone; a verifier
  needs no call back to us or to the issuer.
- **Byte-identical across languages.** The Python (`algovoi-compliance-gate-a2a`) and Node
  (`@algovoi/compliance-gate-a2a`) implementations produce the same `receipt_ref` for the
  same input — enforced in CI against a pinned golden.

## Why we're posting it

We originally offered this edition to the A2A project (`a2aproject/A2A#1887`) and to the
x402 / AP2 spec repos. There was no uptake, so rather than let it sit, we're publishing it
openly as a reference for anyone building compliance evidence into agent payments. No
strings, no account, no telemetry — Apache-2.0.

## Try it

```bash
# clone and run the cross-language parity check
python -m pip install ./python
cd typescript && npm ci && npm run build && cd ..
python tests/test_parity.py    # python golden
node   tests/parity.mjs        # same bytes in Node
```

See the Python and TypeScript READMEs for the full API and a worked example.

## License

Apache-2.0. Contributions and forks welcome; attribution is all we ask.
