"""algovoi-compliance-gate-a2a.x402_rail -- the open x402 payment-rail *format and method*.

The openly-licensed (Apache-2.0) companion to the Compliance Receipt: the byte-discipline
for constructing a spec-correct, multi-lane **x402 v2 `402` challenge**, the **MPP
`application/problem+json` (RFC 9457)** payment-required body, and the rail's **discovery**
surfaces. This is deliberately NOT a settlement engine: it constructs the *advertised*
payment terms; it holds no keys, signs nothing on-chain, and settles nothing. The operator
supplies the payout address per lane; how a payment is verified and settled is out of scope.

It captures four correctness lessons the AlgoVoi rail learned in production, each a pure,
recomputable transform:

1. Per-lane **native decimals**. USDC is not 6-decimal everywhere -- Stellar USDC is
   7-decimal. The advertised ``extra.decimals`` MUST match the scale of the advertised
   ``maxAmountRequired`` (``native_amount``), or a client reads a 10x-wrong price. A guard
   asserts ``amount / 10**decimals == the intended USDC price`` on every lane.
2. **MPP over RFC 9457**. The MPP payment-required body is served as
   ``application/problem+json`` with ``status: 402`` and an ``accepts`` member.
3. **Dash-clean output**. Outward strings carry no em/en dashes (a canonicalisation and
   copy-hygiene guard); ``assert_ascii_dashes_only`` rejects them.
4. **Multi-lane, multi-face discovery**. One ``accepts[]`` entry per enabled lane, and one
   discovery document describing the faces (x402 / mpp / ap2 / a2a) a rail speaks.

Every content-addressed reference reuses the same JCS (RFC 8785) + SHA-256 discipline as the
Compliance Receipt (``sha256_jcs``), and the Python and Node builders emit byte-identical
JSON (same ``challenge_ref``).
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from . import SHA256_PREFIX, sha256_jcs

X402_VERSION = 2
MPP_PROBLEM_MEDIA_TYPE = "application/problem+json"
USDC_CANONICAL_DECIMALS = 6  # the rail prices in 6-decimal microUSDC; lanes rescale from this

# Em dash, en dash, figure dash, horizontal bar, minus sign, non-breaking hyphen.
_DASH_CHARS = "—–‒―−‑"

_SCHEME_KINDS = frozenset({
    "eip3009-exact",       # stock EVM EIP-3009 signed authorization (Base, Monad, ...)
    "solana-reference",    # Solana: server reference pubkey welded into the transfer
    "avm-note",            # Algorand/VOI: challenge welded into the tx note
    "tron-trc20-memo",     # Tron TRC-20 memo weld
})

# Faces a rail can speak. The discovery document advertises the enabled subset.
KNOWN_FACES = ("x402", "mpp", "ap2", "a2a")


class X402RailError(ValueError):
    """Raised when an input violates the x402-rail format discipline."""


# ── dash guard (outward copy hygiene) ─────────────────────────────────────────
def assert_ascii_dashes_only(text: str, *, field: str = "text") -> str:
    """Reject em/en/figure dashes in an outward-facing string. Returns ``text`` unchanged
    when clean, so it composes inside a builder expression."""
    if not isinstance(text, str):
        raise X402RailError(f"{field} must be a string")
    bad = [c for c in _DASH_CHARS if c in text]
    if bad:
        raise X402RailError(
            f"{field} contains a non-ASCII dash ({', '.join(hex(ord(c)) for c in bad)}); "
            "use a plain ASCII hyphen, comma, or parentheses in advertised copy"
        )
    return text


def strip_dashes(text: str) -> str:
    """Replace every em/en/figure dash with ', ' (the rail's outward-copy convention)."""
    out = text
    for c in _DASH_CHARS:
        out = out.replace(c, ", ")
    return out


# ── native decimals: rescale a 6-decimal microUSDC price to a lane's minor units ──
def native_amount(price_micro: int, decimals: int) -> int:
    """Rescale a canonical 6-decimal microUSDC ``price_micro`` to a lane whose USDC has
    ``decimals`` minor units. Stellar USDC is 7-decimal, so 0.01 USDC (10000 micro) becomes
    100000. Raises rather than silently truncating when ``decimals < 6``."""
    if isinstance(price_micro, bool) or not isinstance(price_micro, int) or price_micro <= 0:
        raise X402RailError("price_micro must be a positive integer (6-decimal microUSDC)")
    if isinstance(decimals, bool) or not isinstance(decimals, int) or decimals < 0:
        raise X402RailError("decimals must be a non-negative integer")
    shift = decimals - USDC_CANONICAL_DECIMALS
    if shift >= 0:
        return price_micro * (10 ** shift)
    factor = 10 ** (-shift)
    if price_micro % factor != 0:
        raise X402RailError(
            f"price_micro={price_micro} cannot be represented at {decimals} decimals without loss"
        )
    return price_micro // factor


def _assert_price_agrees(amount_native: int, decimals: int, price_micro: int) -> None:
    """Guard: the advertised (amount, decimals) must equal the intended USDC price exactly."""
    # amount_native / 10**decimals == price_micro / 10**6, checked in integers (no float).
    if amount_native * (10 ** USDC_CANONICAL_DECIMALS) != price_micro * (10 ** decimals):
        raise X402RailError(
            f"advertised amount {amount_native} at {decimals} decimals disagrees with the "
            f"intended {price_micro} microUSDC price"
        )


# ── lane -> one x402 v2 accept ────────────────────────────────────────────────
def build_accept(
    *,
    network: str,
    asset: str,
    pay_to: str,
    resource: str,
    price_micro: int,
    decimals: int = USDC_CANONICAL_DECIMALS,
    scheme_kind: str = "eip3009-exact",
    max_timeout_seconds: int = 120,
    description: str = "",
    extra: Mapping[str, Any] | None = None,
) -> dict:
    """Build ONE x402 v2 ``accepts[]`` entry for a single lane.

    ``network`` is the canonical CAIP-2 id; ``asset`` the on-chain USDC contract/asset id;
    ``pay_to`` the operator's payout address on that lane (caller-supplied, never baked);
    ``price_micro`` the price in 6-decimal microUSDC. The advertised ``maxAmountRequired`` is
    rescaled to the lane's native minor units and ``extra.decimals`` is set to match, with a
    guard proving they agree. ``description`` is dash-checked."""
    for name, val in (("network", network), ("asset", asset), ("pay_to", pay_to), ("resource", resource)):
        if not isinstance(val, str) or not val:
            raise X402RailError(f"{name} must be a non-empty string")
    if scheme_kind not in _SCHEME_KINDS:
        raise X402RailError(f"scheme_kind must be one of {sorted(_SCHEME_KINDS)}, got {scheme_kind!r}")
    amount_native = native_amount(price_micro, decimals)
    _assert_price_agrees(amount_native, decimals, price_micro)
    merged_extra: dict[str, Any] = {"name": "USDC", "decimals": decimals, "scheme_kind": scheme_kind}
    if extra:
        merged_extra.update(extra)
    if "decimals" in (extra or {}) and merged_extra["decimals"] != decimals:
        raise X402RailError("extra.decimals must not override the lane's native decimals")
    return {
        "scheme": "exact",
        "network": network,
        "maxAmountRequired": str(amount_native),
        "asset": asset,
        "payTo": pay_to,
        "maxTimeoutSeconds": max_timeout_seconds,
        "mimeType": "application/json",
        "resource": resource,
        "description": assert_ascii_dashes_only(description, field="description"),
        "outputSchema": None,
        "extra": merged_extra,
    }


# ── the x402 v2 402 challenge (one accept per enabled lane) ───────────────────
def build_x402_challenge(accepts: Iterable[Mapping[str, Any]], *, error: str = "") -> dict:
    """Assemble the strict x402 v2 ``402`` body from one or more ``accepts`` (built by
    ``build_accept``). ``error`` is optional human-readable context (dash-checked)."""
    accepts_list = [dict(a) for a in accepts]
    if not accepts_list:
        raise X402RailError("a 402 challenge needs at least one accept")
    body: dict[str, Any] = {"x402Version": X402_VERSION, "accepts": accepts_list}
    if error:
        body["error"] = assert_ascii_dashes_only(error, field="error")
    return body


# ── MPP payment-required as RFC 9457 application/problem+json ─────────────────
def build_mpp_problem(
    accepts: Iterable[Mapping[str, Any]],
    *,
    detail: str = "Payment required to access this resource.",
    type_uri: str = "https://paymentauth.org/mpp/problems/payment-required",
    title: str = "Payment Required",
    instance: str | None = None,
) -> dict:
    """Build the MPP payment-required body as an RFC 9457 problem object (served with media
    type ``application/problem+json`` and HTTP status 402). Carries the same ``accepts`` as
    the x402 challenge under a problem-extension member so an MPP client picks a lane."""
    accepts_list = [dict(a) for a in accepts]
    if not accepts_list:
        raise X402RailError("an MPP problem needs at least one accept")
    problem: dict[str, Any] = {
        "type": type_uri,
        "title": assert_ascii_dashes_only(title, field="title"),
        "status": 402,
        "detail": assert_ascii_dashes_only(detail, field="detail"),
        "accepts": accepts_list,
    }
    if instance is not None:
        if not isinstance(instance, str) or not instance:
            raise X402RailError("instance must be a non-empty string when provided")
        problem["instance"] = instance
    return problem


# ── discovery surfaces ────────────────────────────────────────────────────────
def build_well_known_x402(resource_urls: Iterable[str], *, instructions: str = "") -> dict:
    """The ``/.well-known/x402`` descriptor: ``{version, resources, ownershipProofs}``."""
    resources = list(resource_urls)
    if not all(isinstance(u, str) and u for u in resources):
        raise X402RailError("every resource url must be a non-empty string")
    body: dict[str, Any] = {"version": 1, "resources": resources, "ownershipProofs": []}
    if instructions:
        body["instructions"] = assert_ascii_dashes_only(instructions, field="instructions")
    return body


def build_discovery_resource(
    *,
    resource: str,
    accepts: Iterable[Mapping[str, Any]],
    faces: Iterable[str],
    last_updated: str,
    input_schema: Mapping[str, Any] | None = None,
) -> dict:
    """One Bazaar-shaped discovery entry for a payable resource. ``faces`` is the subset of
    KNOWN_FACES the rail speaks for this resource (advertised, dedup-preserving order)."""
    if not isinstance(resource, str) or not resource:
        raise X402RailError("resource must be a non-empty string")
    accepts_list = [dict(a) for a in accepts]
    if not accepts_list:
        raise X402RailError("a discovery resource needs at least one accept")
    seen: list[str] = []
    for f in faces:
        if f not in KNOWN_FACES:
            raise X402RailError(f"unknown face {f!r}; known faces are {list(KNOWN_FACES)}")
        if f not in seen:
            seen.append(f)
    if not seen:
        raise X402RailError("a discovery resource must advertise at least one face")
    entry: dict[str, Any] = {
        "resource": resource,
        "type": "http",
        "x402Version": X402_VERSION,
        "faces": seen,
        "lastUpdated": last_updated,
        "accepts": accepts_list,
    }
    if input_schema is not None:
        entry["extensions"] = {"bazaar": {"info": {"input": {"type": "http", "method": "POST"}},
                                          "schema": dict(input_schema)}}
    return entry


# ── content-addressed reference (byte-parity with the Node builder) ───────────
def challenge_ref(challenge: Mapping[str, Any]) -> str:
    """challenge_ref = "sha256:" + SHA-256(JCS(RFC 8785)(challenge)). Recomputable from the
    challenge alone; identical bytes in Python and Node."""
    return SHA256_PREFIX + sha256_jcs(challenge)


def verify_challenge_ref(challenge: Mapping[str, Any], claimed: str) -> bool:
    try:
        return challenge_ref(challenge) == claimed
    except Exception:
        return False


__all__ = [
    "X402_VERSION", "MPP_PROBLEM_MEDIA_TYPE", "USDC_CANONICAL_DECIMALS", "KNOWN_FACES",
    "X402RailError", "assert_ascii_dashes_only", "strip_dashes", "native_amount",
    "build_accept", "build_x402_challenge", "build_mpp_problem",
    "build_well_known_x402", "build_discovery_resource",
    "challenge_ref", "verify_challenge_ref",
]
