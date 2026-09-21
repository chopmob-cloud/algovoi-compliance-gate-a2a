#!/usr/bin/env python3
"""Build a multi-lane x402 402 challenge, the MPP RFC 9457 problem body, and a discovery
entry, then bind a Compliance Receipt to the same resource. Pure format/method: no keys,
no settlement. Run: PYTHONPATH=python python examples/x402_rail_402.py
"""
from __future__ import annotations

import json

from algovoi_compliance_gate_a2a.x402_rail import (
    build_accept,
    build_x402_challenge,
    build_mpp_problem,
    build_discovery_resource,
    build_well_known_x402,
    challenge_ref,
    MPP_PROBLEM_MEDIA_TYPE,
)

RESOURCE = "https://pay.example/verify/receipt"

# One accept per enabled lane. payTo is the OPERATOR's payout address (caller-supplied,
# never baked into the library). USDC contract / EIP-712 domain / CAIP-2 are public facts.
base = build_accept(
    network="eip155:8453",
    asset="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # Circle USDC on Base (public)
    pay_to="0xYOUR_BASE_PAYOUT_ADDRESS",
    resource=RESOURCE,
    price_micro=10000,  # 0.01 USDC, canonical 6-decimal microUSDC
    decimals=6,
    scheme_kind="eip3009-exact",
    description="pay 0.01 USDC on Base via a stock EIP-3009 signed authorization",
    extra={"eip712_domain": {"name": "USD Coin", "version": "2", "chainId": 8453}},
)
stellar = build_accept(
    network="stellar:pubnet",
    asset="USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",  # public issuer
    pay_to="GYOUR_STELLAR_PAYOUT_ADDRESS",
    resource=RESOURCE,
    price_micro=10000,  # still 0.01 USDC ...
    decimals=7,         # ... but Stellar USDC is 7-decimal, so amount rescales to 100000
    scheme_kind="avm-note",
    description="pay 0.01 USDC on Stellar (USDC is 7-decimal here)",
)

challenge = build_x402_challenge([base, stellar], error="Payment required")
print("== x402 v2 402 challenge ==")
print(json.dumps(challenge, indent=2))
print("challenge_ref:", challenge_ref(challenge))

print("\n== per-lane native decimals (both advertise 0.01 USDC) ==")
for a in challenge["accepts"]:
    amt = int(a["maxAmountRequired"])
    dec = a["extra"]["decimals"]
    print(f"  {a['network']:14s} amount={amt:>7d} decimals={dec} -> {amt / 10 ** dec:.2f} USDC")

print(f"\n== MPP payment-required ({MPP_PROBLEM_MEDIA_TYPE}, HTTP 402) ==")
print(json.dumps(build_mpp_problem([base, stellar], detail="Pay to verify this receipt."), indent=2))

print("\n== discovery: /.well-known/x402 + one multi-face resource ==")
print(json.dumps(build_well_known_x402([RESOURCE], instructions="Anonymous x402 pay-per-call."), indent=2))
print(json.dumps(build_discovery_resource(
    resource=RESOURCE,
    accepts=[base, stellar],
    faces=["x402", "mpp", "ap2", "a2a"],
    last_updated="2026-09-21T00:00:00Z",
), indent=2))
