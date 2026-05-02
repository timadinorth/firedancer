/* falcon3_xkcp.c - Falcon-512 verification, scalar.
 *
 * `falcon1_xkcp`'s lazy Barrett NTT, restructured in plain C so the
 * loop vectorizer in clang and gcc can pick up SIMD on its own:
 *
 *   - All pointer parameters carry __restrict__, so the (u, v) halves
 *     of every butterfly are non-aliasing.
 *   - The pass loop is unrolled per stride, so the inner trip count
 *     `t` is a compile-time constant in every body.  The generic
 *     large-stride pass (t = 8 .. 256) is wrapped in a `static inline`
 *     callee that the compiler specialises per call site.
 *   - The three small-stride passes (t = 4, 2, 1 in fwd; symmetric
 *     in inv) are peeled into their own bodies with a unit-stride
 *     outer loop over butterfly *blocks* and explicit unrolling
 *     across blocks within each iteration.  This mirrors the SIMD
 *     reorganization in §3.4 of the paper but in pure C: no SIMD
 *     intrinsics, no platform-specific code.  Whether the compiler
 *     emits AVX2 / AVX-512 for these loops is exactly the auto-vec
 *     test the bench measures.
 *
 * Same Barrett `fq_mul`, same lazy-reduction bounds, same parsers
 * (Pornin `modq_decode` / `comp_decode`), and same XKCP plain64
 * SHAKE256 backend as `falcon1_xkcp`.  This file therefore verifies
 * exactly the same set of signatures as `falcon_ref_xkcp` and
 * `falcon1_xkcp`.
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
#define K_REJ        ( ( 1 << 16 ) / Q )
#define SHAKE_RATE   136

#define BARRETT_M    43687U
#define BARRETT_K    29

typedef uint32_t fq_t;
typedef uint32_t falcon_fq_t;
#include "falcon_twiddle.h"

extern size_t falcon_inner_modq_decode( uint16_t * x, unsigned logn,
                                        void const * in, size_t max_in_len );
extern size_t falcon_inner_comp_decode( int16_t  * x, unsigned logn,
                                        void const * in, size_t max_in_len );

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

static inline fq_t
fq_mul( fq_t a, fq_t b ) {
  uint32_t product = a * b;
  uint64_t wide    = (uint64_t)product * (uint64_t)BARRETT_M;
  uint32_t qest    = (uint32_t)( wide >> BARRETT_K );
  uint32_t r       = product - qest * (uint32_t)Q;
  uint32_t d       = r - (uint32_t)Q;
  return d + ( (uint32_t)Q & (uint32_t)( (int32_t)d >> 31 ) );
}

/* ---------- Forward NTT ----------
 *
 * Generic pass for stride t >= 8.  Marked `inline` so the compiler can
 * specialise on the compile-time-constant `t` at every call site below.
 *
 * The pu / pv pointers cover disjoint length-t slices of `buf`, and the
 * __restrict__ qualifier states that no other access in this function
 * aliases either slice.  Inside the inner loop:
 *   - pu[j] and pv[j] are unit-stride.
 *   - The only loop-carried dependence is per-element (pu[j] alone),
 *     not across j.
 * Both clang and gcc widen this loop to AVX-512 zmm at -O3 -march=native.
 */
static inline void
ntt_fwd_pass( fq_t * __restrict__ buf, uint32_t m, uint32_t t,
              falcon_fq_t const * __restrict__ twiddle ) {
  for( uint32_t i=0; i<m; i++ ) {
    fq_t   s  = twiddle[ m + i ];
    fq_t * __restrict__ pu = buf + 2*i*t;
    fq_t * __restrict__ pv = pu + t;
    for( uint32_t j=0; j<t; j++ ) {
      fq_t u = pu[ j ];
      fq_t v = fq_mul( pv[ j ], s );
      pu[ j ] = u + v;
      pv[ j ] = u - v + (uint32_t)Q;
    }
  }
}

/* Small-stride forward passes peeled.  We hand-unroll across butterfly
 * blocks (the outer `i` axis) so the compiler sees long unit-stride
 * stores into adjacent positions of `buf`. */

/* Stride t=4: 64 blocks of 8 elements, one twiddle per block. */
static inline void
ntt_fwd_pass_t4( fq_t * __restrict__ buf,
                 falcon_fq_t const * __restrict__ twiddle ) {
  for( uint32_t i=0; i<64; i++ ) {
    fq_t s = twiddle[ 64 + i ];
    fq_t * __restrict__ p = buf + 8*i;
    fq_t u0 = p[0], u1 = p[1], u2 = p[2], u3 = p[3];
    fq_t v0 = fq_mul( p[4], s );
    fq_t v1 = fq_mul( p[5], s );
    fq_t v2 = fq_mul( p[6], s );
    fq_t v3 = fq_mul( p[7], s );
    p[0] = u0 + v0;             p[1] = u1 + v1;
    p[2] = u2 + v2;             p[3] = u3 + v3;
    p[4] = u0 - v0 + (uint32_t)Q; p[5] = u1 - v1 + (uint32_t)Q;
    p[6] = u2 - v2 + (uint32_t)Q; p[7] = u3 - v3 + (uint32_t)Q;
  }
}

/* Stride t=2: 128 blocks of 4 elements, one twiddle per block.  Process
 * 4 blocks (16 elements) per outer iteration so the compiler has a
 * full zmm-wide store target. */
static inline void
ntt_fwd_pass_t2( fq_t * __restrict__ buf,
                 falcon_fq_t const * __restrict__ twiddle ) {
  for( uint32_t i=0; i<128; i+=4 ) {
    fq_t s0 = twiddle[ 128 + i + 0 ];
    fq_t s1 = twiddle[ 128 + i + 1 ];
    fq_t s2 = twiddle[ 128 + i + 2 ];
    fq_t s3 = twiddle[ 128 + i + 3 ];
    fq_t * __restrict__ p = buf + 4*i;
    fq_t u00 = p[ 0], u01 = p[ 1], v00 = fq_mul( p[ 2], s0 ), v01 = fq_mul( p[ 3], s0 );
    fq_t u10 = p[ 4], u11 = p[ 5], v10 = fq_mul( p[ 6], s1 ), v11 = fq_mul( p[ 7], s1 );
    fq_t u20 = p[ 8], u21 = p[ 9], v20 = fq_mul( p[10], s2 ), v21 = fq_mul( p[11], s2 );
    fq_t u30 = p[12], u31 = p[13], v30 = fq_mul( p[14], s3 ), v31 = fq_mul( p[15], s3 );
    p[ 0] = u00 + v00;             p[ 1] = u01 + v01;
    p[ 2] = u00 - v00 + (uint32_t)Q; p[ 3] = u01 - v01 + (uint32_t)Q;
    p[ 4] = u10 + v10;             p[ 5] = u11 + v11;
    p[ 6] = u10 - v10 + (uint32_t)Q; p[ 7] = u11 - v11 + (uint32_t)Q;
    p[ 8] = u20 + v20;             p[ 9] = u21 + v21;
    p[10] = u20 - v20 + (uint32_t)Q; p[11] = u21 - v21 + (uint32_t)Q;
    p[12] = u30 + v30;             p[13] = u31 + v31;
    p[14] = u30 - v30 + (uint32_t)Q; p[15] = u31 - v31 + (uint32_t)Q;
  }
}

/* Stride t=1: 256 blocks of 2 elements, one twiddle per block.  Process
 * 8 blocks (16 elements) per outer iteration for a zmm-wide store. */
static inline void
ntt_fwd_pass_t1( fq_t * __restrict__ buf,
                 falcon_fq_t const * __restrict__ twiddle ) {
  for( uint32_t i=0; i<256; i+=8 ) {
    falcon_fq_t const * __restrict__ s = twiddle + 256 + i;
    fq_t * __restrict__ p = buf + 2*i;
    fq_t u0 = p[ 0], v0 = fq_mul( p[ 1], s[0] );
    fq_t u1 = p[ 2], v1 = fq_mul( p[ 3], s[1] );
    fq_t u2 = p[ 4], v2 = fq_mul( p[ 5], s[2] );
    fq_t u3 = p[ 6], v3 = fq_mul( p[ 7], s[3] );
    fq_t u4 = p[ 8], v4 = fq_mul( p[ 9], s[4] );
    fq_t u5 = p[10], v5 = fq_mul( p[11], s[5] );
    fq_t u6 = p[12], v6 = fq_mul( p[13], s[6] );
    fq_t u7 = p[14], v7 = fq_mul( p[15], s[7] );
    p[ 0] = u0 + v0; p[ 1] = u0 - v0 + (uint32_t)Q;
    p[ 2] = u1 + v1; p[ 3] = u1 - v1 + (uint32_t)Q;
    p[ 4] = u2 + v2; p[ 5] = u2 - v2 + (uint32_t)Q;
    p[ 6] = u3 + v3; p[ 7] = u3 - v3 + (uint32_t)Q;
    p[ 8] = u4 + v4; p[ 9] = u4 - v4 + (uint32_t)Q;
    p[10] = u5 + v5; p[11] = u5 - v5 + (uint32_t)Q;
    p[12] = u6 + v6; p[13] = u6 - v6 + (uint32_t)Q;
    p[14] = u7 + v7; p[15] = u7 - v7 + (uint32_t)Q;
  }
}

static void
ntt_fwd_scalar( fq_t * __restrict__ out, fq_t const * __restrict__ in ) {
  fq_t buf[ N ] __attribute__((aligned(64)));
  memcpy( buf, in, sizeof buf );

  ntt_fwd_pass   ( buf,  1, 256, falcon_psi_positive );
  ntt_fwd_pass   ( buf,  2, 128, falcon_psi_positive );
  ntt_fwd_pass   ( buf,  4,  64, falcon_psi_positive );
  ntt_fwd_pass   ( buf,  8,  32, falcon_psi_positive );
  ntt_fwd_pass   ( buf, 16,  16, falcon_psi_positive );
  ntt_fwd_pass   ( buf, 32,   8, falcon_psi_positive );
  ntt_fwd_pass_t4( buf,         falcon_psi_positive );
  ntt_fwd_pass_t2( buf,         falcon_psi_positive );
  ntt_fwd_pass_t1( buf,         falcon_psi_positive );

  /* Final reduction pass: multiply by 1 to get [0, Q). */
  for( uint32_t j=0; j<(uint32_t)N; j++ ) out[ j ] = fq_mul( buf[ j ], 1 );
}

/* ---------- Inverse NTT ----------
 *
 * Symmetric to the forward, with the lazy-reduction reset at off_q = 8
 * (passes 3 and 7 of 9).  Same peeling strategy: small-stride passes
 * (t = 1, 2, 4 here) peeled, large-stride passes generic. */

static inline void
ntt_inv_pass( fq_t * __restrict__ buf, uint32_t h, uint32_t t,
              uint32_t off, int reduce_add,
              falcon_fq_t const * __restrict__ twiddle ) {
  uint32_t j1 = 0;
  for( uint32_t i=0; i<h; i++ ) {
    fq_t   s  = twiddle[ h + i ];
    fq_t * __restrict__ pu = buf + j1;
    fq_t * __restrict__ pv = pu + t;
    for( uint32_t j=0; j<t; j++ ) {
      fq_t u    = pu[ j ];
      fq_t v    = pv[ j ];
      fq_t sum  = u + v;
      fq_t diff = fq_mul( u - v + off, s );
      pu[ j ] = reduce_add ? fq_mul( sum, 1 ) : sum;
      pv[ j ] = diff;
    }
    j1 += 2*t;
  }
}

/* Stride t=1 inverse pass: 256 butterflies, one twiddle per pair. */
static inline void
ntt_inv_pass_t1( fq_t * __restrict__ buf, uint32_t off,
                 falcon_fq_t const * __restrict__ twiddle ) {
  for( uint32_t i=0; i<256; i+=8 ) {
    falcon_fq_t const * __restrict__ s = twiddle + 256 + i;
    fq_t * __restrict__ p = buf + 2*i;
    fq_t u0 = p[ 0], v0 = p[ 1];
    fq_t u1 = p[ 2], v1 = p[ 3];
    fq_t u2 = p[ 4], v2 = p[ 5];
    fq_t u3 = p[ 6], v3 = p[ 7];
    fq_t u4 = p[ 8], v4 = p[ 9];
    fq_t u5 = p[10], v5 = p[11];
    fq_t u6 = p[12], v6 = p[13];
    fq_t u7 = p[14], v7 = p[15];
    p[ 0] = u0 + v0;  p[ 1] = fq_mul( u0 - v0 + off, s[0] );
    p[ 2] = u1 + v1;  p[ 3] = fq_mul( u1 - v1 + off, s[1] );
    p[ 4] = u2 + v2;  p[ 5] = fq_mul( u2 - v2 + off, s[2] );
    p[ 6] = u3 + v3;  p[ 7] = fq_mul( u3 - v3 + off, s[3] );
    p[ 8] = u4 + v4;  p[ 9] = fq_mul( u4 - v4 + off, s[4] );
    p[10] = u5 + v5;  p[11] = fq_mul( u5 - v5 + off, s[5] );
    p[12] = u6 + v6;  p[13] = fq_mul( u6 - v6 + off, s[6] );
    p[14] = u7 + v7;  p[15] = fq_mul( u7 - v7 + off, s[7] );
  }
}

/* Stride t=2 inverse pass: 128 butterflies, one twiddle per 2 pairs. */
static inline void
ntt_inv_pass_t2( fq_t * __restrict__ buf, uint32_t off,
                 falcon_fq_t const * __restrict__ twiddle ) {
  for( uint32_t i=0; i<128; i+=4 ) {
    fq_t s0 = twiddle[ 128 + i + 0 ];
    fq_t s1 = twiddle[ 128 + i + 1 ];
    fq_t s2 = twiddle[ 128 + i + 2 ];
    fq_t s3 = twiddle[ 128 + i + 3 ];
    fq_t * __restrict__ p = buf + 4*i;
    fq_t u00=p[ 0],u01=p[ 1],v00=p[ 2],v01=p[ 3];
    fq_t u10=p[ 4],u11=p[ 5],v10=p[ 6],v11=p[ 7];
    fq_t u20=p[ 8],u21=p[ 9],v20=p[10],v21=p[11];
    fq_t u30=p[12],u31=p[13],v30=p[14],v31=p[15];
    p[ 0]=u00+v00;p[ 1]=u01+v01;p[ 2]=fq_mul(u00-v00+off,s0);p[ 3]=fq_mul(u01-v01+off,s0);
    p[ 4]=u10+v10;p[ 5]=u11+v11;p[ 6]=fq_mul(u10-v10+off,s1);p[ 7]=fq_mul(u11-v11+off,s1);
    p[ 8]=u20+v20;p[ 9]=u21+v21;p[10]=fq_mul(u20-v20+off,s2);p[11]=fq_mul(u21-v21+off,s2);
    p[12]=u30+v30;p[13]=u31+v31;p[14]=fq_mul(u30-v30+off,s3);p[15]=fq_mul(u31-v31+off,s3);
  }
}

/* Stride t=4 inverse pass: 64 butterflies, one twiddle per 4 pairs.
 * In the falcon1 schedule, this is pass 2 of 9 with off_q = 4, so
 * reduce_add is 0 here.  We don't bother with the `reduce_add` flag. */
static inline void
ntt_inv_pass_t4( fq_t * __restrict__ buf, uint32_t off,
                 falcon_fq_t const * __restrict__ twiddle ) {
  for( uint32_t i=0; i<64; i++ ) {
    fq_t s = twiddle[ 64 + i ];
    fq_t * __restrict__ p = buf + 8*i;
    fq_t u0=p[0],u1=p[1],u2=p[2],u3=p[3];
    fq_t v0=p[4],v1=p[5],v2=p[6],v3=p[7];
    p[0] = u0 + v0;
    p[1] = u1 + v1;
    p[2] = u2 + v2;
    p[3] = u3 + v3;
    p[4] = fq_mul( u0 - v0 + off, s );
    p[5] = fq_mul( u1 - v1 + off, s );
    p[6] = fq_mul( u2 - v2 + off, s );
    p[7] = fq_mul( u3 - v3 + off, s );
  }
}

static void
ntt_inv_scalar( fq_t * __restrict__ out, fq_t const * __restrict__ in ) {
  fq_t buf[ N ] __attribute__((aligned(64)));
  memcpy( buf, in, sizeof buf );

  /* Same lazy-reduction schedule as `falcon1_xkcp`.  off_q before each
   * pass: 1, 2, 4, 8(*reset*), 1, 2, 4, 8(*reset*), 1.  Reduction (ra=1)
   * triggers at the t=8 and t=128 passes. */
  ntt_inv_pass_t1( buf, 1*Q,                falcon_psi_negative );
  ntt_inv_pass_t2( buf, 2*Q,                falcon_psi_negative );
  ntt_inv_pass_t4( buf, 4*Q,                falcon_psi_negative );
  ntt_inv_pass   ( buf, 32,    8, 8*Q, 1,   falcon_psi_negative );
  ntt_inv_pass   ( buf, 16,   16, 1*Q, 0,   falcon_psi_negative );
  ntt_inv_pass   ( buf,  8,   32, 2*Q, 0,   falcon_psi_negative );
  ntt_inv_pass   ( buf,  4,   64, 4*Q, 0,   falcon_psi_negative );
  ntt_inv_pass   ( buf,  2,  128, 8*Q, 1,   falcon_psi_negative );
  ntt_inv_pass   ( buf,  1,  256, 1*Q, 0,   falcon_psi_negative );

  /* Final normalization by N^{-1} = 12265 mod Q. */
  for( uint32_t j=0; j<(uint32_t)N; j++ ) out[ j ] = fq_mul( buf[ j ], 12265 );
}

/* ---------- hash-to-point: identical to falcon1_xkcp / falcon_ref_xkcp. */
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
falcon3_xkcp_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                               uint8_t const * sm, size_t   smlen,
                               uint8_t const * pk ) {
  if( pk[ 0 ] != 0x00 + LOGN ) return -1;
  uint16_t h_u16[ N ];
  if( falcon_inner_modq_decode( h_u16, LOGN, pk + 1,
                                FALCON_PUBKEY_SIZE - 1 )
      != FALCON_PUBKEY_SIZE - 1 ) return -1;

  if( smlen < 2 + NONCELEN ) return -1;
  size_t sig_len = ( (size_t)sm[ 0 ] << 8 ) | (size_t)sm[ 1 ];
  if( sig_len > smlen - 2 - NONCELEN ) return -1;
  size_t msg_len = smlen - 2 - NONCELEN - sig_len;

  uint8_t const * esig = sm + 2 + NONCELEN + msg_len;
  if( sig_len < 1 || esig[ 0 ] != 0x20 + LOGN ) return -1;

  int16_t sig_i16[ N ];
  if( falcon_inner_comp_decode( sig_i16, LOGN, esig + 1,
                                sig_len - 1 ) != sig_len - 1 ) return -1;

  fq_t c[ N ];
  hash_to_point_xkcp( c, sm + 2, NONCELEN + msg_len );

  fq_t h[ N ], s2[ N ];
  for( int i=0; i<N; i++ ) {
    h[ i ]  = (fq_t)h_u16[ i ];
    int32_t v = (int32_t)sig_i16[ i ];
    s2[ i ] = (fq_t)( v + ( (int32_t)Q & (v >> 31) ) );
  }

  fq_t h_ntt [ N ] __attribute__((aligned(64)));
  fq_t s2_ntt[ N ] __attribute__((aligned(64)));
  fq_t prod  [ N ] __attribute__((aligned(64)));
  fq_t pmm   [ N ] __attribute__((aligned(64)));
  ntt_fwd_scalar( h_ntt,  h  );
  ntt_fwd_scalar( s2_ntt, s2 );
  for( int i=0; i<N; i++ ) prod[ i ] = fq_mul( h_ntt[ i ], s2_ntt[ i ] );
  ntt_inv_scalar( pmm, prod );

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
