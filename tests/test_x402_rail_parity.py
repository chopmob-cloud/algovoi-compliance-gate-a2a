"""Byte-parity for the x402 pay-rail format module: a fixed 2-lane 402 challenge (Base
6-decimal + Stellar 7-decimal) must produce a pinned golden challenge_ref, and the Node
reference implementation must reproduce the same bytes (see tests/x402Rail.parity.mjs).

The Stellar lane exercises the per-lane native-decimals rule: 0.01 USDC is advertised as
amount=100000 with decimals=7, and reads back as 0.01 (not 0.10). Run standalone or under pytest."""
from algovoi_compliance_gate_a2a.x402_rail import (
    build_accept,
    build_x402_challenge,
    build_mpp_problem,
    challenge_ref,
    verify_challenge_ref,
    assert_ascii_dashes_only,
    native_amount,
    X402RailError,
    MPP_PROBLEM_MEDIA_TYPE,
)

RESOURCE = "https://pay.example/verify/receipt"

GOLDEN_CHALLENGE_REF = "sha256:2f21deecebb58077318e700e7d2620fa0b62895b3c4c2a34facc0a4e16236a40"


def _fixture_challenge():
    base = build_accept(
        network="eip155:8453",
        asset="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        pay_to="0xPAYTO_BASE",
        resource=RESOURCE,
        price_micro=10000,
        decimals=6,
        scheme_kind="eip3009-exact",
        description="pay 0.01 USDC on Base",
    )
    stellar = build_accept(
        network="stellar:pubnet",
        asset="USDC-GA5Z...",
        pay_to="GPAYTO_STELLAR",
        resource=RESOURCE,
        price_micro=10000,
        decimals=7,
        scheme_kind="avm-note",
        description="pay 0.01 USDC on Stellar (7-decimal)",
    )
    return base, stellar, build_x402_challenge([base, stellar], error="Payment required")


def test_challenge_ref_matches_golden():
    base, stellar, challenge = _fixture_challenge()
    # Native-decimals rule: advertised amount and decimals agree, both read 0.01 USDC.
    assert base["maxAmountRequired"] == "10000" and base["extra"]["decimals"] == 6
    assert stellar["maxAmountRequired"] == "100000" and stellar["extra"]["decimals"] == 7
    assert int(base["maxAmountRequired"]) / 10 ** 6 == 0.01
    assert int(stellar["maxAmountRequired"]) / 10 ** 7 == 0.01
    assert challenge_ref(challenge) == GOLDEN_CHALLENGE_REF
    assert verify_challenge_ref(challenge, GOLDEN_CHALLENGE_REF)


def test_native_amount_rescales_and_refuses_loss():
    assert native_amount(10000, 6) == 10000
    assert native_amount(10000, 7) == 100000
    # 6-decimal micro price that cannot be represented at fewer decimals must raise, not truncate.
    try:
        native_amount(10001, 4)
    except X402RailError:
        pass
    else:
        raise AssertionError("expected X402RailError on lossy rescale")


def test_mpp_problem_is_rfc9457_shaped():
    _, _, _ = _fixture_challenge()
    base, stellar, _ = _fixture_challenge()
    problem = build_mpp_problem([base, stellar], detail="Pay to verify this receipt.")
    assert MPP_PROBLEM_MEDIA_TYPE == "application/problem+json"
    assert problem["status"] == 402
    assert problem["type"].startswith("https://") and problem["title"] == "Payment Required"
    assert problem["accepts"][0]["scheme"] == "exact"


def test_dash_guard_rejects_em_dash():
    try:
        assert_ascii_dashes_only("pay 0.01 USDC — fast", field="description")
    except X402RailError:
        pass
    else:
        raise AssertionError("expected X402RailError on em dash")


if __name__ == "__main__":
    test_challenge_ref_matches_golden()
    test_native_amount_rescales_and_refuses_loss()
    test_mpp_problem_is_rfc9457_shaped()
    test_dash_guard_rejects_em_dash()
    print("python OK", GOLDEN_CHALLENGE_REF)
