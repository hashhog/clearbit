// SPDX-License-Identifier: MIT
//
// SHA-256 Intel SHA Extensions (SHA-NI) single-block transform.
//
// Adapted from Bitcoin Core's sha256_x86_shani.cpp (MIT-licensed), which is
// itself based on Jeffrey Walton's SHA-Intrinsics reference code, in turn based
// on Intel and miTLS/Sean Gulley sources (all public domain). The core inner
// loop is the widely verified "SHA-NI single block" reference; we only flatten
// it into plain C (no C++ namespaces, no templates) for Zig FFI.
//
// This file is only compiled on x86_64 targets that support SHA-NI; the
// corresponding flags (-msse4.1 -mssse3 -msha) must be passed by the build
// system. Callers MUST do their own runtime CPUID gate before invoking.

#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>

static const uint8_t __attribute__((aligned(16))) SHANI_MASK[16] = {
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x06, 0x05, 0x04,
    0x0b, 0x0a, 0x09, 0x08,
    0x0f, 0x0e, 0x0d, 0x0c,
};

static inline __attribute__((always_inline)) void
QuadRound(__m128i *state0, __m128i *state1, __m128i m,
          uint64_t k1, uint64_t k0)
{
    const __m128i msg = _mm_add_epi32(m, _mm_set_epi64x((long long)k1, (long long)k0));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, _mm_shuffle_epi32(msg, 0x0e));
}

static inline __attribute__((always_inline)) void
ShiftMessageA(__m128i *m0, __m128i m1)
{
    *m0 = _mm_sha256msg1_epu32(*m0, m1);
}

static inline __attribute__((always_inline)) void
ShiftMessageC(__m128i m0, __m128i m1, __m128i *m2)
{
    *m2 = _mm_sha256msg2_epu32(_mm_add_epi32(*m2, _mm_alignr_epi8(m1, m0, 4)), m1);
}

static inline __attribute__((always_inline)) void
ShiftMessageB(__m128i *m0, __m128i m1, __m128i *m2)
{
    ShiftMessageC(*m0, m1, m2);
    ShiftMessageA(m0, m1);
}

static inline __attribute__((always_inline)) void
Shuffle(__m128i *s0, __m128i *s1)
{
    const __m128i t1 = _mm_shuffle_epi32(*s0, 0xB1);
    const __m128i t2 = _mm_shuffle_epi32(*s1, 0x1B);
    *s0 = _mm_alignr_epi8(t1, t2, 0x08);
    *s1 = _mm_blend_epi16(t2, t1, 0xF0);
}

static inline __attribute__((always_inline)) void
Unshuffle(__m128i *s0, __m128i *s1)
{
    const __m128i t1 = _mm_shuffle_epi32(*s0, 0x1B);
    const __m128i t2 = _mm_shuffle_epi32(*s1, 0xB1);
    *s0 = _mm_blend_epi16(t1, t2, 0xF0);
    *s1 = _mm_alignr_epi8(t2, t1, 0x08);
}

static inline __attribute__((always_inline)) __m128i
LoadMsg(const unsigned char *in)
{
    return _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)in),
                            _mm_load_si128((const __m128i *)SHANI_MASK));
}

// Exported: SHA-256 block transform. Processes `blocks` consecutive 64-byte
// chunks starting at `chunk`, updating `s[0..7]` (big-endian-word state).
void clearbit_sha256_shani_transform(uint32_t *s, const unsigned char *chunk, size_t blocks)
{
    __m128i m0, m1, m2, m3, s0, s1, so0, so1;

    // Load state
    s0 = _mm_loadu_si128((const __m128i *)s);
    s1 = _mm_loadu_si128((const __m128i *)(s + 4));
    Shuffle(&s0, &s1);

    while (blocks--) {
        so0 = s0;
        so1 = s1;

        m0 = LoadMsg(chunk);
        QuadRound(&s0, &s1, m0, 0xe9b5dba5b5c0fbcfULL, 0x71374491428a2f98ULL);
        m1 = LoadMsg(chunk + 16);
        QuadRound(&s0, &s1, m1, 0xab1c5ed5923f82a4ULL, 0x59f111f13956c25bULL);
        ShiftMessageA(&m0, m1);
        m2 = LoadMsg(chunk + 32);
        QuadRound(&s0, &s1, m2, 0x550c7dc3243185beULL, 0x12835b01d807aa98ULL);
        ShiftMessageA(&m1, m2);
        m3 = LoadMsg(chunk + 48);
        QuadRound(&s0, &s1, m3, 0xc19bf1749bdc06a7ULL, 0x80deb1fe72be5d74ULL);
        ShiftMessageB(&m2, m3, &m0);
        QuadRound(&s0, &s1, m0, 0x240ca1cc0fc19dc6ULL, 0xefbe4786e49b69c1ULL);
        ShiftMessageB(&m3, m0, &m1);
        QuadRound(&s0, &s1, m1, 0x76f988da5cb0a9dcULL, 0x4a7484aa2de92c6fULL);
        ShiftMessageB(&m0, m1, &m2);
        QuadRound(&s0, &s1, m2, 0xbf597fc7b00327c8ULL, 0xa831c66d983e5152ULL);
        ShiftMessageB(&m1, m2, &m3);
        QuadRound(&s0, &s1, m3, 0x1429296706ca6351ULL, 0xd5a79147c6e00bf3ULL);
        ShiftMessageB(&m2, m3, &m0);
        QuadRound(&s0, &s1, m0, 0x53380d134d2c6dfcULL, 0x2e1b213827b70a85ULL);
        ShiftMessageB(&m3, m0, &m1);
        QuadRound(&s0, &s1, m1, 0x92722c8581c2c92eULL, 0x766a0abb650a7354ULL);
        ShiftMessageB(&m0, m1, &m2);
        QuadRound(&s0, &s1, m2, 0xc76c51a3c24b8b70ULL, 0xa81a664ba2bfe8a1ULL);
        ShiftMessageB(&m1, m2, &m3);
        QuadRound(&s0, &s1, m3, 0x106aa070f40e3585ULL, 0xd6990624d192e819ULL);
        ShiftMessageB(&m2, m3, &m0);
        QuadRound(&s0, &s1, m0, 0x34b0bcb52748774cULL, 0x1e376c0819a4c116ULL);
        ShiftMessageB(&m3, m0, &m1);
        QuadRound(&s0, &s1, m1, 0x682e6ff35b9cca4fULL, 0x4ed8aa4a391c0cb3ULL);
        ShiftMessageC(m0, m1, &m2);
        QuadRound(&s0, &s1, m2, 0x8cc7020884c87814ULL, 0x78a5636f748f82eeULL);
        ShiftMessageC(m1, m2, &m3);
        QuadRound(&s0, &s1, m3, 0xc67178f2bef9a3f7ULL, 0xa4506ceb90befffaULL);

        s0 = _mm_add_epi32(s0, so0);
        s1 = _mm_add_epi32(s1, so1);

        chunk += 64;
    }

    Unshuffle(&s0, &s1);
    _mm_storeu_si128((__m128i *)s, s0);
    _mm_storeu_si128((__m128i *)(s + 4), s1);
}
