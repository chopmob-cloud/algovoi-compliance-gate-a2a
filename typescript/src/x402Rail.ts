/**
 * @algovoi/compliance-gate-a2a/x402-rail -- the open x402 payment-rail format and method.
 *
 * The openly-licensed (Apache-2.0) companion to the Compliance Receipt: the byte-discipline
 * for constructing a spec-correct, multi-lane x402 v2 `402` challenge, the MPP
 * `application/problem+json` (RFC 9457) payment-required body, and the rail's discovery
 * surfaces. NOT a settlement engine: it constructs the advertised payment terms; it holds no
 * keys, signs nothing on-chain, and settles nothing. The operator supplies the payout address
 * per lane; verification and settlement are out of scope.
 *
 * Four production correctness lessons, each a pure recomputable transform:
 *   1. Per-lane native decimals (USDC is 7-decimal on Stellar, not 6; advertised decimals must
 *      match the scale of maxAmountRequired, or a client reads a 10x-wrong price).
 *   2. MPP over RFC 9457 (application/problem+json, status 402, accepts member).
 *   3. Dash-clean outward strings (no em/en dashes).
 *   4. Multi-lane, multi-face discovery (one accept per enabled lane; faces = x402/mpp/ap2/a2a).
 *
 * Byte-identical to the Python `algovoi_compliance_gate_a2a.x402_rail` module: same JCS
 * (RFC 8785) + SHA-256 discipline (reuses `sha256Jcs`), same output keys, same challenge_ref.
 */
import { SHA256_PREFIX, sha256Jcs, ComplianceGateA2AError } from './index.js';

export const X402_VERSION = 2 as const;
export const MPP_PROBLEM_MEDIA_TYPE = 'application/problem+json' as const;
export const USDC_CANONICAL_DECIMALS = 6 as const;
export const KNOWN_FACES = ['x402', 'mpp', 'ap2', 'a2a'] as const;

// Em dash, en dash, figure dash, horizontal bar, minus sign, non-breaking hyphen.
const DASH_CHARS = ['—', '–', '‒', '―', '−', '‑'];

const SCHEME_KINDS = ['eip3009-exact', 'solana-reference', 'avm-note', 'tron-trc20-memo'] as const;

/** Raised when an input violates the x402-rail format discipline. Shares the repo's error type. */
export class X402RailError extends ComplianceGateA2AError {
  constructor(message: string) {
    super(message);
    this.name = 'X402RailError';
  }
}

// ── dash guard (outward copy hygiene) ─────────────────────────────────────────
export function assertAsciiDashesOnly(text: string, field = 'text'): string {
  if (typeof text !== 'string') throw new X402RailError(`${field} must be a string`);
  const bad = DASH_CHARS.filter((c) => text.includes(c));
  if (bad.length) {
    const hexes = bad.map((c) => '0x' + c.codePointAt(0)!.toString(16)).join(', ');
    throw new X402RailError(
      `${field} contains a non-ASCII dash (${hexes}); use a plain ASCII hyphen, comma, or parentheses in advertised copy`,
    );
  }
  return text;
}

export function stripDashes(text: string): string {
  let out = text;
  for (const c of DASH_CHARS) out = out.split(c).join(', ');
  return out;
}

// ── native decimals: rescale a 6-decimal microUSDC price to a lane's minor units ──
export function nativeAmount(priceMicro: number, decimals: number): number {
  if (!Number.isInteger(priceMicro) || priceMicro <= 0) {
    throw new X402RailError('price_micro must be a positive integer (6-decimal microUSDC)');
  }
  if (!Number.isInteger(decimals) || decimals < 0) {
    throw new X402RailError('decimals must be a non-negative integer');
  }
  const shift = decimals - USDC_CANONICAL_DECIMALS;
  if (shift >= 0) return priceMicro * 10 ** shift;
  const factor = 10 ** -shift;
  if (priceMicro % factor !== 0) {
    throw new X402RailError(
      `price_micro=${priceMicro} cannot be represented at ${decimals} decimals without loss`,
    );
  }
  return priceMicro / factor;
}

function assertPriceAgrees(amountNative: number, decimals: number, priceMicro: number): void {
  // amountNative / 10**decimals == priceMicro / 10**6, checked in integers (no float).
  if (amountNative * 10 ** USDC_CANONICAL_DECIMALS !== priceMicro * 10 ** decimals) {
    throw new X402RailError(
      `advertised amount ${amountNative} at ${decimals} decimals disagrees with the intended ${priceMicro} microUSDC price`,
    );
  }
}

// ── lane -> one x402 v2 accept ────────────────────────────────────────────────
export interface AcceptInput {
  network: string;
  asset: string;
  payTo: string;
  resource: string;
  priceMicro: number;
  decimals?: number;
  schemeKind?: (typeof SCHEME_KINDS)[number];
  maxTimeoutSeconds?: number;
  description?: string;
  extra?: Record<string, unknown>;
}

export function buildAccept(o: AcceptInput): Record<string, unknown> {
  const decimals = o.decimals ?? USDC_CANONICAL_DECIMALS;
  const schemeKind = o.schemeKind ?? 'eip3009-exact';
  for (const [name, val] of [['network', o.network], ['asset', o.asset], ['payTo', o.payTo], ['resource', o.resource]] as const) {
    if (typeof val !== 'string' || !val) throw new X402RailError(`${name} must be a non-empty string`);
  }
  if (!(SCHEME_KINDS as readonly string[]).includes(schemeKind)) {
    throw new X402RailError(`scheme_kind must be one of ${SCHEME_KINDS.join(', ')}, got ${schemeKind}`);
  }
  const amountNative = nativeAmount(o.priceMicro, decimals);
  assertPriceAgrees(amountNative, decimals, o.priceMicro);
  if (o.extra && 'decimals' in o.extra && o.extra.decimals !== decimals) {
    throw new X402RailError("extra.decimals must not override the lane's native decimals");
  }
  const mergedExtra: Record<string, unknown> = { name: 'USDC', decimals, scheme_kind: schemeKind, ...(o.extra ?? {}) };
  return {
    scheme: 'exact',
    network: o.network,
    maxAmountRequired: String(amountNative),
    asset: o.asset,
    payTo: o.payTo,
    maxTimeoutSeconds: o.maxTimeoutSeconds ?? 120,
    mimeType: 'application/json',
    resource: o.resource,
    description: assertAsciiDashesOnly(o.description ?? '', 'description'),
    outputSchema: null,
    extra: mergedExtra,
  };
}

// ── the x402 v2 402 challenge ─────────────────────────────────────────────────
export function buildX402Challenge(
  accepts: Array<Record<string, unknown>>,
  opts: { error?: string } = {},
): Record<string, unknown> {
  const acceptsList = accepts.map((a) => ({ ...a }));
  if (!acceptsList.length) throw new X402RailError('a 402 challenge needs at least one accept');
  const body: Record<string, unknown> = { x402Version: X402_VERSION, accepts: acceptsList };
  if (opts.error) body.error = assertAsciiDashesOnly(opts.error, 'error');
  return body;
}

// ── MPP payment-required as RFC 9457 application/problem+json ─────────────────
export interface MppProblemOpts {
  detail?: string;
  typeUri?: string;
  title?: string;
  instance?: string;
}

export function buildMppProblem(
  accepts: Array<Record<string, unknown>>,
  opts: MppProblemOpts = {},
): Record<string, unknown> {
  const acceptsList = accepts.map((a) => ({ ...a }));
  if (!acceptsList.length) throw new X402RailError('an MPP problem needs at least one accept');
  const problem: Record<string, unknown> = {
    type: opts.typeUri ?? 'https://paymentauth.org/mpp/problems/payment-required',
    title: assertAsciiDashesOnly(opts.title ?? 'Payment Required', 'title'),
    status: 402,
    detail: assertAsciiDashesOnly(opts.detail ?? 'Payment required to access this resource.', 'detail'),
    accepts: acceptsList,
  };
  if (opts.instance !== undefined) {
    if (typeof opts.instance !== 'string' || !opts.instance) {
      throw new X402RailError('instance must be a non-empty string when provided');
    }
    problem.instance = opts.instance;
  }
  return problem;
}

// ── discovery surfaces ────────────────────────────────────────────────────────
export function buildWellKnownX402(
  resourceUrls: string[],
  opts: { instructions?: string } = {},
): Record<string, unknown> {
  const resources = [...resourceUrls];
  if (!resources.every((u) => typeof u === 'string' && u)) {
    throw new X402RailError('every resource url must be a non-empty string');
  }
  const body: Record<string, unknown> = { version: 1, resources, ownershipProofs: [] };
  if (opts.instructions) body.instructions = assertAsciiDashesOnly(opts.instructions, 'instructions');
  return body;
}

export interface DiscoveryResourceInput {
  resource: string;
  accepts: Array<Record<string, unknown>>;
  faces: string[];
  lastUpdated: string;
  inputSchema?: Record<string, unknown>;
}

export function buildDiscoveryResource(o: DiscoveryResourceInput): Record<string, unknown> {
  if (typeof o.resource !== 'string' || !o.resource) throw new X402RailError('resource must be a non-empty string');
  const acceptsList = o.accepts.map((a) => ({ ...a }));
  if (!acceptsList.length) throw new X402RailError('a discovery resource needs at least one accept');
  const seen: string[] = [];
  for (const f of o.faces) {
    if (!(KNOWN_FACES as readonly string[]).includes(f)) {
      throw new X402RailError(`unknown face ${f}; known faces are ${KNOWN_FACES.join(', ')}`);
    }
    if (!seen.includes(f)) seen.push(f);
  }
  if (!seen.length) throw new X402RailError('a discovery resource must advertise at least one face');
  const entry: Record<string, unknown> = {
    resource: o.resource,
    type: 'http',
    x402Version: X402_VERSION,
    faces: seen,
    lastUpdated: o.lastUpdated,
    accepts: acceptsList,
  };
  if (o.inputSchema !== undefined) {
    entry.extensions = { bazaar: { info: { input: { type: 'http', method: 'POST' } }, schema: { ...o.inputSchema } } };
  }
  return entry;
}

// ── content-addressed reference (byte-parity with the Python builder) ─────────
export function challengeRef(challenge: Record<string, unknown>): string {
  return SHA256_PREFIX + sha256Jcs(challenge);
}

export function verifyChallengeRef(challenge: Record<string, unknown>, claimed: string): boolean {
  try {
    return challengeRef(challenge) === claimed;
  } catch {
    return false;
  }
}
