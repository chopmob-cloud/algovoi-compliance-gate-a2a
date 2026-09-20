# @algovoi/compliance-gate-a2a

The open, A2A-interoperable edition of the AlgoVoi **Compliance Gate**: a no-PII,
geo-bound, **seven-field Compliance Receipt** mapped to the A2A Payment Mandate and
Cart Mandate primitives. Apache-2.0.

This is deliberately the **receipt format and method**, not a screening engine. Your
operator supplies the categorical verdict (`ALLOW` / `REFER` / `DENY`) from whichever
screener you already run; this library canonicalises it into a recomputable,
content-addressed Compliance Receipt and binds it to A2A/AP2 mandates by reference.

Published as an open reference (offered to the A2A ecosystem, `a2aproject/A2A#1887`).
Provider-neutral by design: the screening provider names itself in `screenProviderDid`,
and geo resolution is a pluggable `GeoProvider` (MaxMind GeoLite2 / IP2Location in
production, an in-memory table for offline tests).

## The seven-field Compliance Receipt

```
canonVersion, geoRef, jurisdictionFlags, payerRef,
screenProviderDid, screenResult, screenTimestampMs
```

Every reference is `"sha256:" + SHA-256(JCS(RFC 8785)(fields))` — the same
canonicalization A2A already mandates for Agent Card signing (spec section 8.4.1). The
distinctive field is `geoRef`: a first-class, content-addressed geo determination
(resolved country + ASN + provenance), so a verifier sees which jurisdiction a decision
was made against. **No raw IP or address is ever recorded.** The Python
(`algovoi-compliance-gate-a2a`) and Node reference implementations produce byte-identical
receipts (same `receiptRef`) on a clean box.

## Install

```bash
npm install @algovoi/compliance-gate-a2a
```

## Usage

```ts
import {
  InMemoryGeoProvider, resolveGeoRef, payerRef,
  complianceReceipt, receiptRef, toA2aExtension, verifyReceiptRef,
} from "@algovoi/compliance-gate-a2a";

// Geo resolution is pluggable; production injects a MaxMind/IP2Location provider.
const geo = new InMemoryGeoProvider([
  { cidr: "203.0.113.0/24", country: "GB", asn: 64500 },
]);
const { geoRef } = resolveGeoRef(geo, {
  ip: "203.0.113.7",                 // used only to resolve country/ASN, then discarded
  geoSourceDid: "did:web:algovoi.co.uk",
  resolvedAtMs: 1719412800000,
});

const receipt = complianceReceipt({
  payerRef: payerRef("eip155:8453", "0xabc..."),
  screenResult: "ALLOW",                                // your operator supplies this
  screenProviderDid: "did:web:your-screener.example",   // your provider names itself
  screenTimestampMs: 1719412800000,
  jurisdictionFlags: ["ofac", "eu"],                    // ordered screening scope
  geoRef,
});

console.log(receiptRef(receipt));   // "sha256:..."  (recomputable; byte-identical in Python)
verifyReceiptRef(receipt, receiptRef(receipt)); // true, with no issuer contact

// Bind to AP2 mandates by their own handles, under AlgoVoi's A2A extension URI.
const ext = toA2aExtension({
  receipt, paymentMandateId: "pm_123", cartHash: "sha256:...",
});
```

## What this is and is not

- **Is:** an Apache-2.0 receipt format + A2A/AP2 binding + a pluggable geo determination.
- **Is not:** a sanctions/AML screening engine. You supply `screenResult`; this library
  never decides the verdict for you.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
