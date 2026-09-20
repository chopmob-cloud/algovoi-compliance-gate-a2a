/**
 * @algovoi/compliance-gate-a2a -- the open, A2A-interoperable edition of the AlgoVoi
 * Compliance Gate.
 *
 * The openly-licensed (Apache-2.0) receipt format and method offered to the A2A ecosystem
 * (a2aproject/A2A#1887). NOT the screening engine: the operator supplies the categorical
 * screen_result; this module canonicalises it into a recomputable, no-PII seven-field
 * Compliance Receipt and binds it to A2A's Payment Mandate and Cart Mandate primitives.
 *
 * The distinctive field is `geo_ref` -- a first-class, content-addressed geo determination
 * (resolved country + ASN + provenance) produced by AlgoVoi's geo setup. No raw IP is retained.
 *
 * Byte-identical to algovoi-compliance-gate-a2a (Python): snake_case keys, JCS (RFC 8785) +
 * SHA-256, integer epoch-ms hashed directly.
 */
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

export const SHA256_PREFIX = 'sha256:' as const;
export const CANON_VERSION = 'jcs-rfc8785-v1' as const;
export const SCREEN_RESULTS = ['ALLOW', 'REFER', 'DENY'] as const;
export const GEO_METHODS = ['ip-geolocation', 'asserted', 'kyc-derived'] as const;
export const A2A_EXTENSION_URI = 'https://algovoi.co.uk/a2a/extensions/compliance-gate/v1' as const;

export class ComplianceGateA2AError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ComplianceGateA2AError';
  }
}

export function sha256Jcs(obj: unknown): string {
  const s = canonicalize(obj);
  if (s === undefined) throw new ComplianceGateA2AError('not JCS-canonicalisable');
  return createHash('sha256').update(s).digest('hex');
}

// ── our geo setup (ported from algovoi-edge-sentinel) ────────────────────────
export interface GeoLocation { country: string | null; asn: number | null; }
export interface GeoProvider { resolve(ip: string): GeoLocation; }

interface CidrEntry { cidr: string; country?: string | null; asn?: number | null; }

/** Resolve from an in-memory IPv4 CIDR table; longest-prefix match wins. Production injects a
 * MaxMind / IP2Location provider instead. (IPv4 only, sufficient for the offline fixtures.) */
export class InMemoryGeoProvider implements GeoProvider {
  private nets: Array<{ base: number; mask: number; prefix: number; country: string | null; asn: number | null }> = [];

  constructor(entries: CidrEntry[]) {
    for (const e of entries) {
      const [ip, prefixStr] = e.cidr.split('/');
      const prefix = Number(prefixStr);
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      const base = (InMemoryGeoProvider.ipToInt(ip) & mask) >>> 0;
      this.nets.push({ base, mask, prefix, country: e.country ?? null, asn: e.asn ?? null });
    }
    this.nets.sort((a, b) => b.prefix - a.prefix);
  }

  private static ipToInt(ip: string): number {
    const p = ip.split('.').map(Number);
    return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  }

  resolve(ip: string): GeoLocation {
    if (isIP(ip) !== 4) return { country: null, asn: null };
    const v = InMemoryGeoProvider.ipToInt(ip);
    for (const n of this.nets) {
      if (((v & n.mask) >>> 0) === n.base) return { country: n.country, asn: n.asn };
    }
    return { country: null, asn: null };
  }
}

// ── geo determination -> geo_ref ─────────────────────────────────────────────
export interface GeoDetermination {
  asn: number | null;
  country: string | null;
  geo_source_did: string;
  method: string;
  resolved_at_ms: number;
}

export interface GeoDeterminationInput {
  country: string | null;
  asn: number | null;
  geoSourceDid: string;
  method: string;
  resolvedAtMs: number;
}

export function geoDetermination(o: GeoDeterminationInput): GeoDetermination {
  if (!(GEO_METHODS as readonly string[]).includes(o.method)) {
    throw new ComplianceGateA2AError(`method must be one of ${GEO_METHODS.join(', ')}, got ${o.method}`);
  }
  if (o.country !== null && (typeof o.country !== 'string' || !/^[A-Za-z]{2}$/.test(o.country))) {
    throw new ComplianceGateA2AError('country must be an ISO-3166 alpha-2 code or null');
  }
  if (o.asn !== null && (!Number.isInteger(o.asn))) {
    throw new ComplianceGateA2AError('asn must be an integer or null');
  }
  if (!Number.isInteger(o.resolvedAtMs) || o.resolvedAtMs < 0) {
    throw new ComplianceGateA2AError('resolved_at_ms must be a non-negative epoch-millisecond integer');
  }
  if (typeof o.geoSourceDid !== 'string' || !o.geoSourceDid) {
    throw new ComplianceGateA2AError('geo_source_did must be a non-empty string');
  }
  return {
    asn: o.asn,
    country: o.country === null ? null : o.country.toUpperCase(),
    geo_source_did: o.geoSourceDid,
    method: o.method,
    resolved_at_ms: o.resolvedAtMs,
  };
}

export function geoRef(determination: GeoDetermination): string {
  return SHA256_PREFIX + sha256Jcs(determination);
}

export function resolveGeoRef(
  provider: GeoProvider,
  o: { ip: string; geoSourceDid: string; method?: string; resolvedAtMs: number },
): { determination: GeoDetermination; geoRef: string } {
  const loc = provider.resolve(o.ip);
  const det = geoDetermination({
    country: loc.country, asn: loc.asn, geoSourceDid: o.geoSourceDid,
    method: o.method ?? 'ip-geolocation', resolvedAtMs: o.resolvedAtMs,
  });
  return { determination: det, geoRef: geoRef(det) };
}

// ── geo enforcement: resolved country -> ALLOW / REFER / DENY ────────────────
export function jurisdictionDecision(
  country: string | null,
  denyJurisdictions: string[],
  referJurisdictions: string[] = [],
): string {
  // Geo logic (not the sanctions/AML screening engine): DENY if the resolved country is on the
  // deny list, REFER if on the refer list or unresolved, else ALLOW. Case-insensitive ISO-3166.
  if (country === null) return 'REFER';
  const c = country.toUpperCase();
  if (denyJurisdictions.map((j) => j.toUpperCase()).includes(c)) return 'DENY';
  if (referJurisdictions.map((j) => j.toUpperCase()).includes(c)) return 'REFER';
  return 'ALLOW';
}

// ── payer_ref + seven-field receipt ──────────────────────────────────────────
export function payerRef(network: string, address: string): string {
  // Colon-escaped to prevent ambiguity (e.g. ("a","b:c") vs ("a:b","c")).
  const safeNetwork = network.replace(/:/g, '\\:');
  const safeAddress = address.replace(/:/g, '\\:');
  return SHA256_PREFIX + createHash('sha256').update(`${safeNetwork}:${safeAddress}`).digest('hex');
}

export interface ComplianceReceipt {
  canon_version: string;
  geo_ref: string;
  jurisdiction_flags: string[];
  payer_ref: string;
  screen_provider_did: string;
  screen_result: string;
  screen_timestamp_ms: number;
}

export interface ComplianceReceiptInput {
  payerRef: string;
  screenResult: string;
  screenProviderDid: string;
  screenTimestampMs: number;
  jurisdictionFlags: string[];
  geoRef: string;
  canonVersion?: string;
}

export function complianceReceipt(o: ComplianceReceiptInput): ComplianceReceipt {
  if (!(SCREEN_RESULTS as readonly string[]).includes(o.screenResult)) {
    throw new ComplianceGateA2AError(`screen_result must be one of ${SCREEN_RESULTS.join(', ')}`);
  }
  if (typeof o.payerRef !== 'string' || !o.payerRef.startsWith(SHA256_PREFIX)) {
    throw new ComplianceGateA2AError("payer_ref must be a 'sha256:' reference");
  }
  if (typeof o.geoRef !== 'string' || !o.geoRef.startsWith(SHA256_PREFIX)) {
    throw new ComplianceGateA2AError("geo_ref must be a 'sha256:' reference");
  }
  if (!Number.isInteger(o.screenTimestampMs) || o.screenTimestampMs < 0) {
    throw new ComplianceGateA2AError('screen_timestamp_ms must be a non-negative epoch-millisecond integer');
  }
  return {
    canon_version: o.canonVersion ?? CANON_VERSION,
    geo_ref: o.geoRef,
    jurisdiction_flags: [...o.jurisdictionFlags],
    payer_ref: o.payerRef,
    screen_provider_did: o.screenProviderDid,
    screen_result: o.screenResult,
    screen_timestamp_ms: o.screenTimestampMs,
  };
}

export function receiptRef(receipt: ComplianceReceipt): string {
  return SHA256_PREFIX + sha256Jcs(receipt);
}

// ── A2A mapping: bind to AP2 Payment Mandate + Cart Mandate by their own handles ──
export function toA2aExtension(o: {
  receipt: ComplianceReceipt; paymentMandateId: string; cartHash?: string;
}): Record<string, unknown> {
  // paymentMandateId = AP2 PaymentMandateContents.payment_mandate_id; cartHash = AP2 CartMandate
  // cart_hash (merchant-JWT hash over the cart's canonical JSON). We carry AP2's own identifiers
  // so a verifier matches the actual mandates; our receipt_ref stays content-addressed.
  if (typeof o.paymentMandateId !== 'string' || !o.paymentMandateId) {
    throw new ComplianceGateA2AError('payment_mandate_id must be a non-empty string (AP2 mandate id)');
  }
  const params: Record<string, unknown> = {
    compliance_receipt: o.receipt,
    receipt_ref: receiptRef(o.receipt),
    payment_mandate_id: o.paymentMandateId,
  };
  if (o.cartHash !== undefined) {
    if (typeof o.cartHash !== 'string' || !o.cartHash) {
      throw new ComplianceGateA2AError('cart_hash must be a non-empty string (AP2 cart_hash)');
    }
    params.cart_hash = o.cartHash;
  }
  return { uri: A2A_EXTENSION_URI, params };
}

// ── verification ─────────────────────────────────────────────────────────────
export function verifyGeoRef(determination: GeoDetermination, claimed: string): boolean {
  try { return geoRef(determination) === claimed; } catch { return false; }
}

export function verifyReceiptRef(receipt: ComplianceReceipt, claimed: string): boolean {
  try { return receiptRef(receipt) === claimed; } catch { return false; }
}
