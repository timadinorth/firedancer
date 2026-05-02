/* falcon1_xkcp.c - Falcon-512 verification, scalar.
 *
 * Starting point: `falcon_ref_xkcp.c` (Pornin parsers + XKCP plain64
 * SHAKE256 in hash-to-point + Pornin's NTT pipeline).  This file
 * applies Improvement 1 from the paper to that baseline:
 *
 *   - Field elements are represented as `uint32_t` in [0, Q).
 *   - Multiplication uses Barrett reduction (M = floor(2^29 / Q)),
 *     not Montgomery, so there is no domain conversion at the NTT
 *     boundaries.
 *   - The forward and inverse butterflies use lazy reduction: only
 *     the multiplication inside the butterfly is Barrett-reduced; the
 *     additions and subtractions accumulate in the wider `uint32_t`
 *     representation (Section "Lazy Reduction" in the paper).
 *
 * Everything else is identical to `falcon_ref_xkcp.c`: parsing comes
 * from the vendored Pornin reference, hash-to-point uses XKCP plain64
 * SHAKE256, the norm check at the end is the one from the paper.
 *
 * No SIMD intrinsics are used.  The point of this variant is to
 * isolate the wall-clock contribution of Improvement 1 over a scalar
 * baseline, so that the bench can compare it directly with
 * `falcon_ref_xkcp` (same SHAKE backend, Pornin's Montgomery NTT) and,
 * if a falcon3 variant is added, with the combined improvements.
 *
 * Public domain.
 */

#include "falcon.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define NONCELEN     40
#define N            FALCON_N
#define LOGN         FALCON_LOGN
#define Q            FALCON_Q
#define BETA2        FALCON_BETA2
#define K_REJ        ( ( 1 << 16 ) / Q ) /* 5 */
#define SHAKE_RATE   136                   /* (1600 - 2*256) / 8 */

#define BARRETT_M    43687U                /* floor(2^29 / Q) */
#define BARRETT_K    29

/* The twiddle tables in falcon_twiddle.h are typed as `falcon_fq_t`,
 * matching falcon_avx512.c.  We use a uint32_t alias here so the same
 * tables drop in with no copy. */
typedef uint32_t fq_t;
typedef uint32_t falcon_fq_t;
#include "falcon_twiddle.h"

/* --- Pornin parsers (vendor/falcon-round3) --- */
extern size_t falcon_inner_modq_decode( uint16_t * x, unsigned logn,
                                        void const * in, size_t max_in_len );
extern size_t falcon_inner_comp_decode( int16_t  * x, unsigned logn,
                                        void const * in, size_t max_in_len );

/* --- XKCP plain64 Keccak-p[1600] (vendor/xkcp) --- */
typedef struct { uint64_t A[ 25 ]; } kp1600_state_t;
extern void KeccakP1600_plain64_Initialize       ( kp1600_state_t * st );
extern void KeccakP1600_plain64_AddBytes         ( kp1600_state_t * st,
                                                   unsigned char const * data,
                                                   unsigned int offset,
                                                   unsigned int length );
extern void KeccakP1600_plain64_Permute_24rounds ( kp1600_state_t * st );
extern void KeccakP1600_plain64_ExtractBytes     ( kp1600_state_t const * st,
                                                   unsigned char * data,
                                                   unsigned int offset,
                                                   unsigned int length );

/* ---------- Barrett reduction (scalar uint32_t).
 *
 * Inputs:  a, b such that a*b fits in uint32_t (i.e. <= 2^32 - 1).
 *          For the lazy NTT below, the worst case we hit is
 *          16 * Q^2 ~= 2.4e9 < 2^32 (inverse butterfly with off_q=8).
 *
 * Output:  a*b mod Q in [0, Q).
 *
 * The scalar Barrett does one 32-bit multiply, one 32x32->64 multiply
 * (mulq on x86-64), one shift, one multiply-subtract, and one
 * conditional subtract.  This is ~6 ops, comparable to Pornin's
 * Montgomery routine.
 */
static inline fq_t
fq_mul( fq_t a, fq_t b ) {
  uint32_t product = a * b;                                  /* mod 2^32 */
  uint64_t wide    = (uint64_t)product * (uint64_t)BARRETT_M;
  uint32_t qest    = (uint32_t)( wide >> BARRETT_K );
  uint32_t r       = product - qest * (uint32_t)Q;           /* in [0, 2Q] */
  uint32_t d       = r - (uint32_t)Q;
  return d + ( (uint32_t)Q & (uint32_t)( (int32_t)d >> 31 ) );
}

/* ---------- Forward NTT, lazy reduction (Section "Lazy Reduction").
 *
 *   Each butterfly:  u' = u + v*s,  v' = u - v*s + Q.
 *   Bound after k passes: 0 <= x < (k+1)*Q.
 *   For LOGN=9 passes, max bound is 10*Q < 2^17, well within 32 bits.
 *   A final pass that multiplies by 1 with the same Barrett routine
 *   reduces every element to [0, Q).
 */
static void
ntt_fwd_scalar( fq_t * out, fq_t const * in ) {
  memcpy( out, in, sizeof(fq_t) * N );

  uint32_t t = N;
  uint32_t m = 1;
  while( m < N ) {
    t >>= 1;
    for( uint32_t i=0; i<m; i++ ) {
      uint32_t j1 = 2 * i * t;
      fq_t     s  = falcon_psi_positive[ m + i ];
      for( uint32_t j=j1; j<j1+t; j++ ) {
        fq_t u = out[ j     ];
        fq_t v = fq_mul( out[ j + t ], s );  /* in [0, Q) */
        out[ j     ] = u + v;                 /* lazy: u' = u + v       */
        out[ j + t ] = u - v + (uint32_t)Q;   /* lazy: v' = u - v + Q   */
      }
    }
    m <<= 1;
  }

  /* Final reduction pass: multiply each element by 1 to get [0, Q). */
  for( uint32_t j=0; j<(uint32_t)N; j++ ) out[ j ] = fq_mul( out[ j ], 1 );
}

/* ---------- Inverse NTT, lazy reduction.
 *
 *   Inverse butterfly:  u' = u + v,  v' = (u - v + off) * s.
 *   off = off_q * Q.  off_q starts at 1 and doubles each pass; when it
 *   reaches 8 the next Barrett product would overflow, so we reduce u'
 *   explicitly and reset off_q to 1.  For the 9-pass schedule this
 *   triggers at passes 3 and 7.  The final pass multiplies by
 *   N^{-1} = 12265 mod Q, which both normalizes the inverse transform
 *   and reduces any remaining lazy values to [0, Q).
 */
static void
ntt_inv_scalar( fq_t * out, fq_t const * in ) {
  memcpy( out, in, sizeof(fq_t) * N );

  uint32_t t     = 1;
  uint32_t m     = N;
  uint32_t off_q = 1;
  while( m > 1 ) {
    uint32_t h          = m >> 1;
    uint32_t off        = off_q * (uint32_t)Q;
    int      reduce_add = ( off_q >= 8 );

    uint32_t j1 = 0;
    for( uint32_t i=0; i<h; i++ ) {
      fq_t s = falcon_psi_negative[ h + i ];
      for( uint32_t j=j1; j<j1+t; j++ ) {
        fq_t u    = out[ j     ];
        fq_t v    = out[ j + t ];
        fq_t sum  = u + v;
        fq_t diff = fq_mul( u - v + off, s );
        out[ j     ] = reduce_add ? fq_mul( sum, 1 ) : sum;
        out[ j + t ] = diff;
      }
      j1 += 2 * t;
    }
    if( reduce_add ) off_q = 1; else off_q <<= 1;
    t <<= 1;
    m >>= 1;
  }

  /* Final normalization by N^{-1} mod Q.  512^{-1} mod Q = 12265. */
  for( uint32_t j=0; j<(uint32_t)N; j++ ) out[ j ] = fq_mul( out[ j ], 12265 );
}

/* ---------- hash-to-point (XKCP plain64 SHAKE256, scalar rejection) ----------
 *
 *  Identical to `hash_to_point_xkcp` in `falcon_ref_xkcp.c`. */
static void
hash_to_point_xkcp( fq_t * out, uint8_t const * in, size_t in_len ) {
  kp1600_state_t st;
  KeccakP1600_plain64_Initialize( &st );

  while( in_len >= SHAKE_RATE ) {
    KeccakP1600_plain64_AddBytes( &st, in, 0, SHAKE_RATE );
    KeccakP1600_plain64_Permute_24rounds( &st );
    in += SHAKE_RATE; in_len -= SHAKE_RATE;
  }
  if( in_len ) KeccakP1600_plain64_AddBytes( &st, in, 0, (unsigned)in_len );
  unsigned char ds  = 0x1F;
  unsigned char fin = 0x80;
  KeccakP1600_plain64_AddBytes( &st, &ds,  (unsigned)in_len,    1 );
  KeccakP1600_plain64_AddBytes( &st, &fin, SHAKE_RATE - 1,       1 );
  KeccakP1600_plain64_Permute_24rounds( &st );

  unsigned remaining = N;
  uint8_t  blk[ SHAKE_RATE ];
  for( ;; ) {
    KeccakP1600_plain64_ExtractBytes( &st, blk, 0, SHAKE_RATE );
    for( unsigned j=0; j+1 < SHAKE_RATE && remaining > 0; j += 2 ) {
      uint32_t w = ( (uint32_t)blk[ j ] << 8 ) | (uint32_t)blk[ j+1 ];
      if( w < (uint32_t)( K_REJ * Q ) ) {
        while( w >= (uint32_t)Q ) w -= (uint32_t)Q;
        *out++ = (fq_t)w;
        remaining--;
      }
    }
    if( !remaining ) break;
    KeccakP1600_plain64_Permute_24rounds( &st );
  }
}

int
falcon1_xkcp_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                               uint8_t const * sm, size_t   smlen,
                               uint8_t const * pk ) {
  /* --- Public-key parsing (Pornin scalar). --- */
  if( pk[ 0 ] != 0x00 + LOGN ) return -1;
  uint16_t h_u16[ N ];
  if( falcon_inner_modq_decode( h_u16, LOGN, pk + 1,
                                FALCON_PUBKEY_SIZE - 1 )
      != FALCON_PUBKEY_SIZE - 1 ) return -1;

  /* --- Find nonce, signature, message length. --- */
  if( smlen < 2 + NONCELEN ) return -1;
  size_t sig_len = ( (size_t)sm[ 0 ] << 8 ) | (size_t)sm[ 1 ];
  if( sig_len > smlen - 2 - NONCELEN ) return -1;
  size_t msg_len = smlen - 2 - NONCELEN - sig_len;

  uint8_t const * esig = sm + 2 + NONCELEN + msg_len;
  if( sig_len < 1 || esig[ 0 ] != 0x20 + LOGN ) return -1;

  /* --- Signature parsing (Pornin scalar). --- */
  int16_t sig_i16[ N ];
  if( falcon_inner_comp_decode( sig_i16, LOGN, esig + 1,
                                sig_len - 1 ) != sig_len - 1 ) return -1;

  /* --- Hash-to-point with XKCP plain64 SHAKE. --- */
  fq_t c[ N ];
  hash_to_point_xkcp( c, sm + 2, NONCELEN + msg_len );

  /* --- Convert h, s2 to uint32_t in [0, Q). --- */
  fq_t h[ N ], s2[ N ];
  for( int i=0; i<N; i++ ) {
    h[ i ]  = (fq_t)h_u16[ i ];
    int32_t v = (int32_t)sig_i16[ i ];
    s2[ i ] = (fq_t)( v + ( (int32_t)Q & (v >> 31) ) );
  }

  /* --- NTT(h) * NTT(s2), then iNTT, with our scalar lazy-reduction
   *     pipeline (Improvement 1). --- */
  fq_t h_ntt [ N ];
  fq_t s2_ntt[ N ];
  fq_t prod  [ N ];
  fq_t pmm   [ N ];
  ntt_fwd_scalar( h_ntt,  h  );
  ntt_fwd_scalar( s2_ntt, s2 );
  for( int i=0; i<N; i++ ) prod[ i ] = fq_mul( h_ntt[ i ], s2_ntt[ i ] );
  ntt_inv_scalar( pmm, prod );

  /* --- Norm check.  All elements in [0, Q); compute s1 = c - pmm
   *     mod Q, normalize each of (s1, s2) to (-Q/2, Q/2], accumulate
   *     squared norm. --- */
  long norm = 0L;
  for( int i=0; i<N; i++ ) {
    uint32_t a    = c  [ i ];
    uint32_t b    = pmm[ i ];
    int      s1   = (int)( ( a >= b ) ? ( a - b ) : ( (uint32_t)Q - b + a ) );
    if( s1 > Q/2 ) s1 -= Q;
    int      s2_s = (int)sig_i16[ i ];
    norm += (long)s1 * s1 + (long)s2_s * s2_s;
  }
  if( norm > BETA2 ) return -1;

  if( m && msg_len ) memmove( m, sm + 2 + NONCELEN, msg_len );
  if( mlen ) *mlen = msg_len;
  return 0;
}
