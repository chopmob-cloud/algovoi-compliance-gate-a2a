"""Byte-parity: the seven-field Compliance Receipt's receipt_ref must equal a pinned
golden value, and the Node reference implementation must reproduce the same bytes
(see tests/parity.mjs). Run standalone or under pytest."""
from algovoi_compliance_gate_a2a import (
    compliance_receipt,
    receipt_ref,
    verify_receipt_ref,
)

GOLDEN_INPUT = dict(
    payer_ref="sha256:aa",
    screen_result="ALLOW",
    screen_provider_did="did:web:x",
    screen_timestamp_ms=1719412800000,
    jurisdiction_flags=["ofac", "eu"],
    geo_ref="sha256:bb",
)
# JCS(RFC 8785) + SHA-256 over the seven-field receipt. Identical in Node.
GOLDEN_RECEIPT_REF = "sha256:517211fb24473a1fe268b70614915aaad036eec85b67abb024a32798f37ec902"


def test_receipt_ref_matches_golden():
    receipt = compliance_receipt(**GOLDEN_INPUT)
    assert set(receipt) == {
        "canon_version", "geo_ref", "jurisdiction_flags", "payer_ref",
        "screen_provider_did", "screen_result", "screen_timestamp_ms",
    }
    assert receipt_ref(receipt) == GOLDEN_RECEIPT_REF
    assert verify_receipt_ref(receipt, GOLDEN_RECEIPT_REF)


if __name__ == "__main__":
    test_receipt_ref_matches_golden()
    print("python OK", GOLDEN_RECEIPT_REF)
