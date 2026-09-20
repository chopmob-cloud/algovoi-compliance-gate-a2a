// Byte-parity: the Node reference implementation must reproduce the exact receipt_ref
// that the Python package produces for the same seven-field receipt (see tests/test_parity.py).
import { complianceReceipt, receiptRef } from "../typescript/dist/index.js";

const GOLDEN = "sha256:517211fb24473a1fe268b70614915aaad036eec85b67abb024a32798f37ec902";

const receipt = complianceReceipt({
  payerRef: "sha256:aa",
  screenResult: "ALLOW",
  screenProviderDid: "did:web:x",
  screenTimestampMs: 1719412800000,
  jurisdictionFlags: ["ofac", "eu"],
  geoRef: "sha256:bb",
});

const got = receiptRef(receipt);
if (got !== GOLDEN) {
  console.error("MISMATCH:", got, "!=", GOLDEN);
  process.exit(1);
}
console.log("node OK", got);
