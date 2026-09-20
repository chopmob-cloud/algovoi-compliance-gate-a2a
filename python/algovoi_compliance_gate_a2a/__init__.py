"""algovoi-compliance-gate-a2a -- the open, A2A-interoperable edition of the AlgoVoi
Compliance Gate.

This is the openly-licensed (Apache-2.0) *receipt format and method* offered to the A2A
ecosystem (a2aproject/A2A#1887). It is deliberately NOT the screening engine: the operator
supplies the categorical screen_result (ALLOW / REFER / DENY) from their own screener; this
module canonicalises it into a recomputable, no-PII Compliance Receipt and binds it to A2A's
Payment Mandate and Cart Mandate primitives by reference.

The seven-field Compliance Receipt:

    canon_version, geo_ref, jurisdiction_flags, payer_ref,
    screen_provider_did, screen_result, screen_timestamp_ms

The distinctive field is ``geo_ref`` -- a first-class, content-addressed *geo determination*
(the payer's resolved country + ASN + provenance), so a verifier can see which jurisdiction
the decision was made against, not just the static screening scope. The geo determination is
produced by AlgoVoi's own geo setup (``GeoProvider``: ip -> {country, asn}; MaxMind/IP2Location
in production, an in-memory CIDR table for offline validation). No raw IP or address is ever
recorded -- only the resolved country, ASN, resolver DID, method, and timestamp.

Every reference is "sha256:" + SHA-256(JCS(RFC 8785)(fields)); integer epoch-milliseconds are
hashed directly (no string conversion). Byte-identical to @algovoi/compliance-gate-a2a (Node).
"""
from __future__ import annotations

import hashlib
import ipaddress
from typing import Iterable, Protocol

import rfc8785

__version__ = "0.1.0"

SHA256_PREFIX = "sha256:"
CANON_VERSION = "jcs-rfc8785-v1"

SCREEN_RESULTS = frozenset({"ALLOW", "REFER", "DENY"})
GEO_METHODS = frozenset({"ip-geolocation", "asserted", "kyc-derived"})

A2A_EXTENSION_URI = "https://algovoi.co.uk/a2a/extensions/compliance-gate/v1"


class ComplianceGateA2AError(ValueError):
    """Raised when an input violates the substrate discipline."""


def sha256_jcs(obj) -> str:
    """SHA-256 over the JCS (RFC 8785) canonical bytes of ``obj`` (hex, no prefix)."""
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


# ── our geo setup (ported from algovoi-edge-sentinel) ────────────────────────
class GeoProvider(Protocol):
    def resolve(self, ip: str) -> dict:
        """Return ``{"country": <ISO-3166 alpha-2 or None>, "asn": <int or None>}``."""
        ...


class InMemoryGeoProvider:
    """Resolve from an in-memory CIDR table. ``entries`` is a list of ``{"cidr","country","asn"}``.
    Longest-prefix match wins; unknown IPs resolve to ``{country: None, asn: None}``. The
    production deployment injects a MaxMind GeoLite2 / IP2Location-backed provider instead."""

    def __init__(self, entries: list[dict]) -> None:
        self._nets: list[tuple] = []
        for e in entries:
            net = ipaddress.ip_network(e["cidr"], strict=False)
            self._nets.append((net, e.get("country"), e.get("asn")))
        self._nets.sort(key=lambda t: t[0].prefixlen, reverse=True)

    def resolve(self, ip: str) -> dict:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"country": None, "asn": None}
        for net, country, asn in self._nets:
            if addr.version == net.version and addr in net:
                return {"country": country, "asn": asn}
        return {"country": None, "asn": None}


# ── geo determination -> geo_ref ─────────────────────────────────────────────
def geo_determination(*, country, asn, geo_source_did: str, method: str,
                      resolved_at_ms: int) -> dict:
    """The no-PII geo determination object. ``country`` is an ISO-3166 alpha-2 code (or None);
    ``asn`` an integer (or None). No IP address is retained -- the determination records only
    the resolved location plus its provenance."""
    if method not in GEO_METHODS:
        raise ComplianceGateA2AError(f"method must be one of {sorted(GEO_METHODS)}, got {method!r}")
    if country is not None and (not isinstance(country, str) or len(country) != 2 or not country.isalpha()):
        raise ComplianceGateA2AError("country must be an ISO-3166 alpha-2 code or None")
    if asn is not None and (isinstance(asn, bool) or not isinstance(asn, int)):
        raise ComplianceGateA2AError("asn must be an integer or None")
    if isinstance(resolved_at_ms, bool) or not isinstance(resolved_at_ms, int) or resolved_at_ms < 0:
        raise ComplianceGateA2AError("resolved_at_ms must be a non-negative epoch-millisecond integer")
    if not isinstance(geo_source_did, str) or not geo_source_did:
        raise ComplianceGateA2AError("geo_source_did must be a non-empty string")
    return {
        "asn": asn,
        "country": (country.upper() if country is not None else None),
        "geo_source_did": geo_source_did,
        "method": method,
        "resolved_at_ms": resolved_at_ms,
    }


def geo_ref(determination: dict) -> str:
    """geo_ref = "sha256:" + SHA-256(JCS({asn, country, geo_source_did, method, resolved_at_ms}))."""
    return SHA256_PREFIX + sha256_jcs(determination)


def resolve_geo_ref(provider: GeoProvider, *, ip: str, geo_source_did: str,
                    method: str = "ip-geolocation", resolved_at_ms: int) -> tuple[dict, str]:
    """Resolve ``ip`` through our geo setup and return (determination, geo_ref). The IP is used
    only to resolve country/ASN and is then discarded -- it never enters the determination."""
    loc = provider.resolve(ip)
    det = geo_determination(country=loc.get("country"), asn=loc.get("asn"),
                            geo_source_did=geo_source_did, method=method,
                            resolved_at_ms=resolved_at_ms)
    return det, geo_ref(det)


# ── geo enforcement: resolved country -> ALLOW / REFER / DENY ────────────────
def jurisdiction_decision(country, deny_jurisdictions, *, refer_jurisdictions=()) -> str:
    """Map a resolved country to a categorical verdict against policy lists (geo enforcement;
    this is geo logic, not the sanctions/AML screening engine).

    DENY if the resolved country is in ``deny_jurisdictions``; REFER if in ``refer_jurisdictions``
    or if the country could not be resolved (jurisdiction unconfirmed); otherwise ALLOW. Country
    matching is case-insensitive; lists hold ISO-3166 alpha-2 codes."""
    if country is None:
        return "REFER"
    c = country.upper()
    if c in {j.upper() for j in deny_jurisdictions}:
        return "DENY"
    if c in {j.upper() for j in refer_jurisdictions}:
        return "REFER"
    return "ALLOW"


# ── payer_ref + seven-field receipt ──────────────────────────────────────────
def payer_ref(network: str, address: str) -> str:
    """Content-addressed, no-PII payer reference: "sha256:" + SHA-256("network:address")
    with colon-escaped components to prevent ambiguity."""
    safe_network = network.replace(":", "\\:")
    safe_address = address.replace(":", "\\:")
    return SHA256_PREFIX + hashlib.sha256(f"{safe_network}:{safe_address}".encode()).hexdigest()


def compliance_receipt(*, payer_ref: str, screen_result: str, screen_provider_did: str,
                       screen_timestamp_ms: int, jurisdiction_flags: Iterable[str],
                       geo_ref: str, canon_version: str = CANON_VERSION) -> dict:
    """Build the validated seven-field Compliance Receipt. ``jurisdiction_flags`` is the gate's
    ordered screening scope (order is byte-load-bearing per RFC 8785); ``geo_ref`` binds the
    payer's resolved geo determination."""
    if screen_result not in SCREEN_RESULTS:
        raise ComplianceGateA2AError(f"screen_result must be one of {sorted(SCREEN_RESULTS)}")
    if not (isinstance(payer_ref, str) and payer_ref.startswith(SHA256_PREFIX)):
        raise ComplianceGateA2AError("payer_ref must be a 'sha256:' reference")
    if not (isinstance(geo_ref, str) and geo_ref.startswith(SHA256_PREFIX)):
        raise ComplianceGateA2AError("geo_ref must be a 'sha256:' reference")
    if isinstance(screen_timestamp_ms, bool) or not isinstance(screen_timestamp_ms, int) or screen_timestamp_ms < 0:
        raise ComplianceGateA2AError("screen_timestamp_ms must be a non-negative epoch-millisecond integer")
    flags = list(jurisdiction_flags)
    return {
        "canon_version": canon_version,
        "geo_ref": geo_ref,
        "jurisdiction_flags": flags,
        "payer_ref": payer_ref,
        "screen_provider_did": screen_provider_did,
        "screen_result": screen_result,
        "screen_timestamp_ms": screen_timestamp_ms,
    }


def receipt_ref(receipt: dict) -> str:
    """receipt_ref = "sha256:" + SHA-256(JCS(receipt))."""
    return SHA256_PREFIX + sha256_jcs(receipt)


# ── A2A mapping: bind the receipt to AP2 Payment Mandate + Cart Mandate ──────
def to_a2a_extension(*, receipt: dict, payment_mandate_id: str,
                     cart_hash: str | None = None) -> dict:
    """Bind a Compliance Receipt to AP2's mandate primitives by their OWN handles, so an A2A/AP2
    verifier matches the binding against the actual mandates in the message, with no fresh
    AlgoVoi hash over their objects:

      - ``payment_mandate_id``: AP2 ``PaymentMandateContents.payment_mandate_id`` (the mandate's
        own identifier).
      - ``cart_hash``: AP2 ``CartMandate`` ``cart_hash`` -- the merchant-JWT hash over the cart's
        canonical JSON -- when a cart is present.

    Our own artifact stays content-addressed: ``receipt_ref`` = "sha256:" + SHA-256(JCS(receipt))
    is recomputable from the receipt alone. Emitted as an A2A extension object under our own URI
    namespace (never inside an A2A/AP2 controlled namespace)."""
    if not (isinstance(payment_mandate_id, str) and payment_mandate_id):
        raise ComplianceGateA2AError("payment_mandate_id must be a non-empty string (AP2 mandate id)")
    params = {
        "compliance_receipt": receipt,
        "receipt_ref": receipt_ref(receipt),
        "payment_mandate_id": payment_mandate_id,
    }
    if cart_hash is not None:
        if not (isinstance(cart_hash, str) and cart_hash):
            raise ComplianceGateA2AError("cart_hash must be a non-empty string (AP2 cart_hash)")
        params["cart_hash"] = cart_hash
    return {"uri": A2A_EXTENSION_URI, "params": params}


# ── verification ─────────────────────────────────────────────────────────────
def verify_geo_ref(determination: dict, claimed: str) -> bool:
    try:
        return geo_ref(determination) == claimed
    except Exception:
        return False


def verify_receipt_ref(receipt: dict, claimed: str) -> bool:
    try:
        return receipt_ref(receipt) == claimed
    except Exception:
        return False


__all__ = [
    "__version__", "SHA256_PREFIX", "CANON_VERSION", "SCREEN_RESULTS", "GEO_METHODS",
    "A2A_EXTENSION_URI", "ComplianceGateA2AError", "sha256_jcs",
    "GeoProvider", "InMemoryGeoProvider",
    "geo_determination", "geo_ref", "resolve_geo_ref", "jurisdiction_decision",
    "payer_ref", "compliance_receipt", "receipt_ref", "to_a2a_extension",
    "verify_geo_ref", "verify_receipt_ref",
]
