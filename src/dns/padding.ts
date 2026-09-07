// RFC 8467 response padding. We pad by adding an EDNS Padding option (code 12)
// into the response's existing OPT RR — the only RFC-correct way for a proxy
// that must not alter the answer section. Messages without an OPT RR are left
// untouched (adding one would change semantics).

import { parseSections, toView } from "./wire.js";

export const PADDING_OPTION_CODE = 12;
export const PADDING_BLOCK_SIZE = 128;

/**
 * Pads `msg` so its total length is a multiple of PADDING_BLOCK_SIZE by
 * inserting an EDNS padding option into the existing OPT RR. Returns the
 * original message when there is no OPT RR or the message is malformed.
 */
export function padResponse(msg: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  // Already aligned → assume padded; adding more would break idempotency.
  if (msg.length % PADDING_BLOCK_SIZE === 0) return msg;
  const parsed = parseSections(msg);
  if (!parsed) return msg;
  const opt = parsed.additional.rrs.find((rr) => rr.rrType === 41);
  if (!opt) return msg;

  // Amount of padding needed to bring the final message to a block boundary.
  const optionOverhead = 4; // OPTION-CODE(2) + OPTION-LENGTH(2)
  const padLen = (PADDING_BLOCK_SIZE - ((msg.length + optionOverhead) % PADDING_BLOCK_SIZE)) % PADDING_BLOCK_SIZE;

  const option = new Uint8Array(4 + padLen);
  const view = toView(option);
  view.setUint16(0, PADDING_OPTION_CODE);
  view.setUint16(2, padLen);
  // remaining bytes are zero padding

  const rdataEnd = opt.rdataOffset + opt.rdLength;
  const out = new Uint8Array(msg.length + option.length);
  out.set(msg.subarray(0, rdataEnd), 0);
  out.set(option, rdataEnd);
  out.set(msg.subarray(rdataEnd), rdataEnd + option.length);
  const outView = toView(out);
  outView.setUint16(opt.rdataOffset - 2, opt.rdLength + option.length);
  return out;
}
