// RFC 3161 timestamp of the packet signature (SPEC.md §2.5) — same scope as
// the reference implementation, honestly stated: we build the request and
// structurally check the grant (status 0/1, our digest echoed inside); we
// do NOT validate the token's CMS signature — that is the receiver's job
// (`openssl ts -verify`). The TSA sees a signature hash, never content.

import crypto from "node:crypto";

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest();

/// DER TimeStampReq: SEQUENCE { version 1, MessageImprint { sha256 AlgId,
/// OCTET STRING digest }, certReq TRUE }. Byte-identical to
/// `openssl ts -query -sha256 -no_nonce -cert`.
export function requestDer(digest32) {
  return Buffer.concat([
    Buffer.from("3039020101303130 0d06096086480165 0304020105000420".replace(/ /g, ""), "hex"),
    digest32,
    Buffer.from("0101ff", "hex"),
  ]);
}

function derHeader(buf, at) {
  const first = buf[at + 1];
  if (first === undefined) return null;
  if (first < 0x80) return [at + 2, first];
  const n = first & 0x7f;
  if (n === 0 || n > 4 || at + 2 + n > buf.length) return null;
  let len = 0;
  for (let i = 0; i < n; i++) len = len * 256 + buf[at + 2 + i];
  return [at + 2 + n, len];
}

/// Minimal structural check of a TimeStampResp — NOT cryptographic.
export function checkResponse(resp, digest32) {
  if (resp[0] !== 0x30) throw new Error("TSA response is not a DER SEQUENCE");
  const outer = derHeader(resp, 0);
  if (!outer) throw new Error("malformed TSA response");
  const statusAt = outer[0];
  if (resp[statusAt] !== 0x30) throw new Error("missing PKIStatusInfo");
  const info = derHeader(resp, statusAt);
  if (!info || resp[info[0]] !== 0x02) throw new Error("missing PKIStatus");
  const int = derHeader(resp, info[0]);
  if (!int || int[1] !== 1) throw new Error("unexpected PKIStatus width");
  const status = resp[int[0]];
  if (status > 1) throw new Error(`TSA refused the request (PKIStatus ${status})`);
  if (info[0] + info[1] >= resp.length) throw new Error("granted status but no token in response");
  if (!resp.includes(digest32)) throw new Error("token does not echo the requested digest");
}

/// Fetch the packet's `timestamp` member for a signature. Failure throws —
/// the user opted in; a packet silently missing it would misrepresent what
/// they asked to produce.
export async function obtain(tsaUrl, signatureBytes) {
  const digest = sha256(signatureBytes);
  const resp = await fetch(tsaUrl, {
    method: "POST",
    headers: { "Content-Type": "application/timestamp-query" },
    body: requestDer(digest),
    signal: AbortSignal.timeout(15_000),
  });
  if (!resp.ok) throw new Error(`TSA HTTP ${resp.status}`);
  const token = Buffer.from(await resp.arrayBuffer());
  checkResponse(token, digest);
  return {
    type: "rfc3161",
    tsaUrl,
    hashAlg: "sha256",
    messageImprint: digest.toString("hex"),
    token: token.toString("base64"),
  };
}
