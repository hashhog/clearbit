# W122 — BIP-158 GCS codec stress-vector audit (clearbit)

**Date:** 2026-05-17
**Scope:** Golomb-Rice writer/reader at quotients NOT exercised by
Core's `blockfilters.json` test data.
**Reference bug:** haskoin W121 addendum BUG-16 / FIX-69
(`bitWriterWrite` silently dropped bits when
`numBits + bwBits > 64` — found only via stress vectors at q ≥ 64).

## Status

**VERIFIED CLEAN.** clearbit's GCS codec round-trips correctly at every
synthesized quotient boundary tested (q ∈ {0, 1, 63, 64, 65, 100, 200,
1000, 65536}) and produces byte-identical output to a hand-computed
reference at q=64 and q=128.

## Codec status

GCS codec is **PRESENT** in clearbit (`src/indexes.zig:188-348`):

- `BitStreamWriter` (line 195): MSB-first byte-aligned bit packer
- `BitStreamReader` (line 285): MSB-first byte-aligned bit reader
- `golombRiceEncode` (line 247): unary quotient batched at 57 bits
  per `writeBits` call (Core uses 64; output is bit-identical)
- `golombRiceDecode` (line 333): bit-by-bit unary count + P-bit
  remainder
- `GCSFilter` (line 364): full encode/match path with ElementSet dedup

Note: per W121, P2P getcfilters/cfilter handlers and BIP-324 short-ID
codec wiring are **ABSENT** (W121 BUGs 3-7). The codec itself is
intact; what's missing is wire-format dispatch on the P2P side. W122
is scoped only to codec correctness, which is testable in isolation.

## Why haskoin's bug class can't apply here

haskoin BUG-16 was a **Word64-granularity** bug: the Haskell writer
accumulated bits into a `Word64` buffer and only flushed when the
buffer was full. With non-zero starting offset `bwBits`, the
expression `maskedValue << bwBits` silently dropped the top `bwBits`
bits whenever `numBits + bwBits > 64`.

clearbit's writer accumulates into a **`u8` buffer** that flushes
every 8 bits (`indexes.zig:233-237`). The cross-boundary arithmetic
operates on bit-slices of width ≤ 8, never approaching the u64
boundary. The relevant shifts in `writeBits` (lines 227-229) use
`u6`-typed shift amounts capped at 63, so no shift-by-64 trap.

Independently verifiable via the stress vectors below.

## Stress vectors added

15 new tests in `src/tests_w122_gcs_stress.zig`, wired via
`zig build test-w122` and folded into the default `test` step:

| Test | Quotient | What it stresses |
|---|---|---|
| w122 G1 | q=0 | No unary bits |
| w122 G2 | q=1 | Single unary 1 |
| w122 G3 | q=63 | Just below 64-bit batch boundary |
| w122 G4 | q=64 | Exact 64-bit batch boundary |
| w122 G5 | q=64 after non-aligned prior write | Tightest haskoin-BUG-16 analog |
| w122 G6 | q=65 | One past batch boundary |
| w122 G7 | q=100 | Multi-chunk loop |
| w122 G8 | q=200 | 4 writer chunks |
| w122 G9 | q=1000 | 18 writer chunks |
| w122 G10 | sequence{0,1,63,64,65,100,200,1000} | Back-to-back boundary stack |
| w122 G11 | q=64, byte-exact | Reference-cross-check |
| w122 G12 | 256 random elements | End-to-end GCSFilter encode+match |
| w122 G13 | testnet3 genesis | Core blockfilters.json regression |
| w122 G14 | q=65536 | Writer chunk-loop heavy stress |
| w122 G15 | q=128, byte-exact | Chunk-size invariance vs Core |

Result: **15/15 tests pass** under `zig build test-w122` (Zig 0.13 Debug).

## Hand-traced encoder behavior at q=64

Encoder input: delta = `(64 << 19) | 0` = `0x2000000`.

- `q = delta >> 19 = 64`
- `ones_left = 64`. Loop:
  - batch 1: min(64, 57) = 57 ones, written via `writeBits(~0, 57)`
  - batch 2: min(7, 57) = 7 ones, written via `writeBits(~0, 7)`
- terminating zero: `writeBit(false)` (1 bit)
- remainder: `writeBits(0, 19)` (19 bits)

Total bits: 64 + 1 + 19 = 84. Padded to 88 = 11 bytes.

Byte layout (verified by G11):
```
0x00..0x07 = 0xFF * 8         (64 ones)
0x08       = 0b0_0000000       (0-bit + top 7 of 19-bit zero r)
0x09       = 0x00              (next 8 of r)
0x0A       = 0b0000_0000       (last 4 of r + 4 pad bits)
```

Reader reads 64 unary 1-bits, terminating 0, then 19 zero bits →
returns `(64 << 19) | 0` = `0x2000000`. Round-trip exact.

## Known potential trap (not exercised by realistic filters)

`golombRiceDecode` line 341: `(q << p) | r`. For pathologically large
q (e.g. q ≥ 2^(64-p) from a corrupted/adversarial filter), the shift
would overflow u64. In Zig 0.13 ReleaseFast this wraps silently; in
Debug it would panic.

**Realistic bound:** with F = N*M ≤ 2^32 * 784931 ≈ 2^52, max hash
delta ≤ 2^52, max q ≤ 2^52 / 2^19 = 2^33. So `q << 19` ≤ 2^52,
comfortably within u64. The trap requires malicious filter data.

**Mitigation:** none currently. Filter-data consumers should validate
N ≤ MAX_FILTER_N before decoding, which clearbit does NOT do
explicitly (the bound is implicit in N being u32 and M being u32).
Flagging as **non-blocking note** — outside W122 scope, candidate for
a future hardening wave if filter-data ingestion ever processes
untrusted streams without an outer length check.

## Conclusion

clearbit's BIP-158 Golomb-Rice codec is **VERIFIED CLEAN** against the
W122 stress-vector battery. The haskoin BUG-16 class of failure
(Word64-boundary truncation) is structurally inapplicable because
clearbit's bit buffer is u8-granular, and the 57-vs-64-bit chunk
choice produces bit-identical output.

No bugs found. No fixes needed.

## Cross-impl context

Per W121 (May 16 2026) every impl with BIP-158 codec passes Core
`blockfilters.json` — codec layer is universally Core-compatible
across the fleet. W122 confirms clearbit's codec is also robust at
quotients Core's vectors don't cover.

Future W### or FIX-### waves remain queued for clearbit's W121
P0-CDIV-P2P gaps:
- BUG-3..BUG-6: getcfilters/cfilters/getcfheaders/cfheaders/
  getcfcheckpt/cfcheckpt P2P handlers ABSENT
- BUG-7: BIP-324 short IDs 22-27 registered but unwired
  (dead-helper-at-BIP-324-message-table pattern from W121)
- BUG-8/9: JSON-RPC getblockfilter / getindexinfo NOT registered
- BUG-10: MAX_GETCFILTERS_SIZE / MAX_GETCFHEADERS_SIZE /
  CFCHECKPT_INTERVAL constants ABSENT
