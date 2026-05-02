/* falcon.h - self-contained Falcon-512 signature verification.
 *
 * Four verifiers are exposed through the NIST PQC API (the same API used
 * by the upstream round 3 reference and by PQClean):
 *
 *   - falcon_ref_*           : the unmodified NIST round 3 reference by
 *                              Thomas Pornin et al., vendored at
 *                              contrib/falcon/vendor/falcon-round3/.
 *   - falcon_ref_xkcp_*      : same as `falcon_ref_*`, but with the
 *                              SHAKE256 used inside hash-to-point
 *                              swapped for XKCP's plain64 SHAKE256
 *                              (vendored at contrib/falcon/vendor/xkcp).
 *                              Bit-for-bit compatible with `falcon_ref`.
 *   - falcon_ref_turbopar_*  : non-standard variant from the paper:
 *                              hash-to-point uses TurboSHAKE256 (12
 *                              rounds of Keccak-p[1600]) with an 8-way
 *                              parallel squeeze on top of XKCP's
 *                              `KeccakP1600times8_AVX512`.  Cannot
 *                              verify standard Falcon round 3
 *                              signatures because the produced `c`
 *                              differs.  Provided for benchmarking.
 *   - falcon_avx512_*        : the AVX-512 implementation described in
 *                              the paper, in this directory.
 *
 * All four functions consume the same NIST "signed message" buffer and
 * the same 897-byte public key, so the bench and the test harness pass
 * the same byte buffers to all of them with no per-call repackaging.
 *
 * Public domain. */

#ifndef CONTRIB_FALCON_FALCON_H
#define CONTRIB_FALCON_FALCON_H

#include <stddef.h>
#include <stdint.h>

#define FALCON_N            512
#define FALCON_LOGN         9
#define FALCON_Q            12289
#define FALCON_BETA2        34034726L

#define FALCON_PUBKEY_SIZE  ( 1 + ( 14 * FALCON_N / 8 ) ) /* 897 */
#define FALCON_SIG_MAX      690                            /* round 3 max */

#ifdef __cplusplus
extern "C" {
#endif

/* NIST API (same prototype as `crypto_sign_open` from the Falcon NIST
   round 3 submission).  On success, the plaintext is written to `m`,
   `*mlen` is set to its length, and 0 is returned.  -1 on any failure
   (parsing, signature verification, output buffer too small).

   `sm`/`smlen` is the NIST signed-message buffer:

     [ sig_len:2 BE | nonce:40 | message:mlen | esig: 1 + comp_s2 ]

   where esig[0] = 0x29 and esig[1..] is the compressed polynomial s2.
   `pk` is the 897-byte public key: [0x09 | 14-bit-packed h[512]]. */

int falcon_ref_crypto_sign_open(          uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

int falcon_ref_xkcp_crypto_sign_open(     uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

int falcon_ref_turbopar_crypto_sign_open( uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

/* Scalar variants of `falcon_ref_xkcp` that apply, in isolation,
 * algorithmic improvements proposed in the paper or in the literature.
 * No SIMD intrinsics: the only platform features used are
 * __builtin_clzll, __builtin_bswap64, and __builtin_*_overflow, which
 * all compile to single x86-64 instructions without AVX-512 enabled.
 *
 *   - falcon1_xkcp : scalar Barrett uint32 NTT with lazy reduction.
 *   - falcon2_xkcp : 64-bit window + lzcnt comp_decode.
 *   - falcon3_xkcp : same NTT as falcon1, restructured (__restrict__,
 *                    peeled small-stride passes) so the C loop
 *                    vectorizer can pick up SIMD on its own.
 *   - falcon4_xkcp : same NTT structure as falcon1, but with the
 *                    field multiplication switched from Barrett to the
 *                    Shoup / Harvey precomputed-twiddle reduction.   */
int falcon1_xkcp_crypto_sign_open(        uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

int falcon2_xkcp_crypto_sign_open(        uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

int falcon3_xkcp_crypto_sign_open(        uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

int falcon4_xkcp_crypto_sign_open(        uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

int falcon_avx512_crypto_sign_open(       uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

/* Same pipeline as `falcon_avx512`; the only difference is that the
 * field multiplication inside the NTT butterflies uses the Shoup /
 * Harvey precomputed-twiddle reduction instead of Barrett.  Used to
 * isolate the Shoup vs. Barrett comparison on top of the AVX-512
 * code path. */
int falcon2_avx512_crypto_sign_open(      uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

/* Same as `falcon2_avx512` but with the two forward NTTs merged: h and
 * s2 are interleaved into a single `combined[2N]` buffer and processed
 * by a single 9-pass loop.  Every pass runs at zmm width because the
 * (h, s2) pair fills the lane that the un-merged code drops to
 * ymm/SSE for at small strides. */
int falcon3_avx512_crypto_sign_open(      uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

/* Hybrid forward NTT: separate per-NTT for the early (large-stride)
 * passes, then merged combined-buffer for the small-stride passes.
 * Four entry points, parameterised by the largest stride at which the
 * merged path is used: m1 merges only t=1, m8 merges t=8,4,2,1. */
int falcon4_avx512_m1_crypto_sign_open(   uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );
int falcon4_avx512_m2_crypto_sign_open(   uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );
int falcon4_avx512_m4_crypto_sign_open(   uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );
int falcon4_avx512_m8_crypto_sign_open(   uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

/* Same merged-forward-NTT structure as `falcon3_avx512` but with
 * Barrett mul instead of Shoup.  Pairs with `falcon_avx512` (Barrett,
 * sequential) the way `falcon3_avx512` pairs with `falcon2_avx512`
 * (Shoup, sequential), so that
 *   falcon5  - falcon_avx512   = merge effect under Barrett
 *   falcon3  - falcon2_avx512  = merge effect under Shoup
 * isolates the Shoup-vs-Barrett benefit at fixed merge structure. */
int falcon5_avx512_crypto_sign_open(      uint8_t       * m, size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk );

#ifdef __cplusplus
}
#endif

#endif /* CONTRIB_FALCON_FALCON_H */
