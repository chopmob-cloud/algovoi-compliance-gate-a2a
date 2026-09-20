"""Wiring the Compliance Gate into a Keystone-style decision, by content-addressed reference.

The Compliance Receipt is never mutated. A decision layer binds to the screen that
preceded it by reference, so the binding recomputes offline from the two references
alone, with no issuer contact. This is consistency (this decision ran against THIS
screen), not correlation.

The chain, all "sha256:" + SHA-256(JCS(RFC 8785)(...)):

    receipt            the seven-field Compliance Receipt (this package)
    screen_ref         receipt_ref(receipt)
    screen_binding_ref sha256 over {decision_ref, screen_ref}     binds a decision to its screen

A full Keystone decision audit then carries this screen_binding_ref alongside its
passport, mandate, and policy references, so one recomputable audit proves the decision
bound this identity, this mandate, this policy snapshot, and this compliance screen. The
commercial AlgoVoi Keystone additionally proves which decision standard drove the verdict
and post-quantum signs the evidence chain; that layer is out of scope for this open edition.

Run:  PYTHONPATH=python python examples/keystone_binding.py
"""
from algovoi_compliance_gate_a2a import (
    InMemoryGeoProvider,
    resolve_geo_ref,
    payer_ref,
    compliance_receipt,
    receipt_ref,
    sha256_jcs,
    SHA256_PREFIX,
)


def screen_binding_ref(decision_ref: str, screen_ref: str) -> str:
    """Bind a decision to the Compliance Receipt (screen) that preceded it.

        screen_binding_ref = "sha256:" + SHA-256(JCS({decision_ref, screen_ref}))

    Both inputs are content-addressed "sha256:" references, so any party recomputes this
    from the two references with no issuer contact and no PII in scope.
    """
    for name, ref in (("decision_ref", decision_ref), ("screen_ref", screen_ref)):
        if not (isinstance(ref, str) and ref.startswith(SHA256_PREFIX)):
            raise ValueError(f"{name} must be a 'sha256:' reference")
    return SHA256_PREFIX + sha256_jcs({"decision_ref": decision_ref, "screen_ref": screen_ref})


def main() -> None:
    # 1) Run the compliance gate: produce the seven-field receipt. The verdict is yours,
    #    from whatever screener you run; the gate canonicalises it, it does not decide it.
    geo = InMemoryGeoProvider([{"cidr": "203.0.113.0/24", "country": "GB", "asn": 64500}])
    _determination, geo_reference = resolve_geo_ref(
        geo,
        ip="203.0.113.7",  # used only to resolve country/ASN, then discarded
        geo_source_did="did:web:algovoi.co.uk",
        resolved_at_ms=1719412800000,
    )
    receipt = compliance_receipt(
        payer_ref=payer_ref("eip155:8453", "0xF00Dcafe00000000000000000000000000000001"),
        screen_result="ALLOW",
        screen_provider_did="did:web:screener.example",
        screen_timestamp_ms=1719412800000,
        jurisdiction_flags=["UK", "EU"],
        geo_ref=geo_reference,
    )

    # 2) receipt_ref is the screen_ref that a decision layer binds.
    screen_ref = receipt_ref(receipt)

    # 3) Bind your Keystone decision to that screen. decision_ref here is a stand-in for
    #    the reference your decision layer already computes.
    decision_ref = SHA256_PREFIX + "11" * 32
    binding = screen_binding_ref(decision_ref, screen_ref)

    print("screen_ref (receipt_ref):", screen_ref)
    print("decision_ref:            ", decision_ref)
    print("screen_binding_ref:      ", binding)

    # 4) A verifier recomputes the binding from the two references, offline.
    assert screen_binding_ref(decision_ref, screen_ref) == binding
    print("verify: screen_binding_ref recomputes from (decision_ref, screen_ref) -> OK")

    # Fold `binding` into your Keystone decision audit as its compliance-screen reference,
    # next to the passport, mandate, and policy references. Leaving it out is byte-identical
    # to the no-compliance path: the binding is purely additive.


if __name__ == "__main__":
    main()
