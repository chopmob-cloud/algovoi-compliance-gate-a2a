// Byte-parity: the Node x402-rail builder must reproduce the exact challenge_ref the Python
// module produces for the same fixed 2-lane 402 challenge (see tests/test_x402_rail_parity.py).
import { buildAccept, buildX402Challenge, challengeRef } from '../typescript/dist/x402Rail.js';

const RESOURCE = 'https://pay.example/verify/receipt';
const GOLDEN = 'sha256:2f21deecebb58077318e700e7d2620fa0b62895b3c4c2a34facc0a4e16236a40';

const base = buildAccept({
  network: 'eip155:8453',
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  payTo: '0xPAYTO_BASE',
  resource: RESOURCE,
  priceMicro: 10000,
  decimals: 6,
  schemeKind: 'eip3009-exact',
  description: 'pay 0.01 USDC on Base',
});
const stellar = buildAccept({
  network: 'stellar:pubnet',
  asset: 'USDC-GA5Z...',
  payTo: 'GPAYTO_STELLAR',
  resource: RESOURCE,
  priceMicro: 10000,
  decimals: 7,
  schemeKind: 'avm-note',
  description: 'pay 0.01 USDC on Stellar (7-decimal)',
});

// Native-decimals rule holds on the Node side too.
if (base.maxAmountRequired !== '10000' || base.extra.decimals !== 6) {
  console.error('MISMATCH base:', base.maxAmountRequired, base.extra.decimals);
  process.exit(1);
}
if (stellar.maxAmountRequired !== '100000' || stellar.extra.decimals !== 7) {
  console.error('MISMATCH stellar:', stellar.maxAmountRequired, stellar.extra.decimals);
  process.exit(1);
}

const challenge = buildX402Challenge([base, stellar], { error: 'Payment required' });
const got = challengeRef(challenge);
if (got !== GOLDEN) {
  console.error('MISMATCH:', got, '!=', GOLDEN);
  process.exit(1);
}
console.log('node OK', got);
