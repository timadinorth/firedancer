/* falcon4_xkcp.c - Falcon-512 verification, scalar.
 *
 * `falcon1_xkcp` with the field multiplication replaced by the
 * Shoup / Harvey precomputed-twiddle reduction.  Everything else
 * (lazy-reduction schedule, Pornin parsers, XKCP plain64 SHAKE256)
 * is identical to falcon1.
 *
 * Shoup multiplication: for each twiddle s in [0, Q), precompute
 *
 *     s' = floor( s * 2^32 / Q )
 *
 * Then to compute v * s mod Q for v in [0, B*Q):
 *
 *     q_hat = floor( v * s' / 2^32 )       // mul-high
 *     r     = v * s - q_hat * Q            // mod 2^32
 *     return r >= Q ? r - Q : r
 *
 * For our worst-case v (v < 16Q in the lazy NTT), the analysis (e.g.
 * Harvey 2014, "Faster arithmetic for NTT-based multiplication")
 * shows v*s - q_hat*Q lies in [0, Q+1), so a single conditional sub
 * normalises to [0, Q).
 *
 * Compared to Barrett, the multiply count per butterfly is the same
 * (3: one for q_hat, one for v*s, one for q_hat*Q), but the critical
 * path is shorter: v*s and q_hat*Q can issue in parallel, while
 * Barrett serialises product -> (product*M)>>K -> qest*Q.  In scalar
 * code on x86-64 the saving is one mul latency per butterfly.
 *
 * The s' tables are derived from the falcon_twiddle.h tables at
 * program start via __attribute__((constructor)).  They live in this
 * file's TU only.
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

/* Shoup-style precomputed multiplier: s' = floor(s * 2^32 / Q). */
static fq_t s_prime_pos[ N ];
static fq_t s_prime_neg[ N ];

/* For the "reduce by 1" multiplications in the lazy-reduction passes
 * we need s' for the constant 1.  And for the iNTT final
 * normalization by N^{-1} = 12265 we need its s'. */
#define S_PRIME_ONE   ( (uint32_t)( ( (uint64_t)1     << 32 ) / Q ) )  /* 349525 */
#define S_PRIME_NINV  ( (uint32_t)( ( (uint64_t)12265 << 32 ) / Q ) )

__attribute__((constructor))
static void
init_shoup_tables( void ) {
  for( int i=0; i<N; i++ ) {
    s_prime_pos[ i ] = (uint32_t)(
        ( (uint64_t)falcon_psi_positive[ i ] << 32 ) / Q );
    s_prime_neg[ i ] = (uint32_t)(
        ( (uint64_t)falcon_psi_negative[ i ] << 32 ) / Q );
  }
}

/* Shoup multiplication: v * s mod Q, given s' = floor(s * 2^32 / Q). */
static inline fq_t
fq_mul_shoup( fq_t v, fq_t s, fq_t s_prime ) {
  uint32_t q_hat = (uint32_t)( ( (uint64_t)v * (uint64_t)s_prime ) >> 32 );
  uint32_t r     = v * s - q_hat * (uint32_t)Q;       /* mod 2^32 */
  uint32_t d     = r - (uint32_t)Q;
  return d + ( (uint32_t)Q & (uint32_t)( (int32_t)d >> 31 ) );
}

/* ---------- Forward NTT, lazy reduction, Shoup multiplication.
 *
 * Same butterfly and same bound as falcon1.  Each butterfly multiplies
 * by twiddle s; we look up the matching s' from `s_prime_pos`. */
static void
ntt_fwd_scalar( fq_t * out, fq_t const * in ) {
  memcpy( out, in, sizeof(fq_t) * N );

  uint32_t t = N;
  uint32_t m = 1;
  while( m < N ) {
    t >>= 1;
    for( uint32_t i=0; i<m; i++ ) {
      fq_t s  = falcon_psi_positive[ m + i ];
      fq_t sp = s_prime_pos        [ m + i ];
      for( uint32_t j=2*i*t; j<2*i*t+t; j++ ) {
        fq_t u = out[ j     ];
        fq_t v = fq_mul_shoup( out[ j + t ], s, sp );
        out[ j     ] = u + v;
        out[ j + t ] = u - v + (uint32_t)Q;
      }
    }
    m <<= 1;
  }

  /* Final reduction pass: multiply by 1 to get [0, Q). */
  for( uint32_t j=0; j<(uint32_t)N; j++ )
    out[ j ] = fq_mul_shoup( out[ j ], 1, S_PRIME_ONE );
}

/* ---------- Inverse NTT, lazy reduction, Shoup multiplication.
 *
 * Same off_q schedule as falcon1: reset at passes 3 and 7 of 9. */
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
      fq_t s  = falcon_psi_negative[ h + i ];
      fq_t sp = s_prime_neg        [ h + i ];
      for( uint32_t j=j1; j<j1+t; j++ ) {
        fq_t u    = out[ j     ];
        fq_t v    = out[ j + t ];
        fq_t sum  = u + v;
        fq_t diff = fq_mul_shoup( u - v + off, s, sp );
        out[ j     ] = reduce_add ? fq_mul_shoup( sum, 1, S_PRIME_ONE ) : sum;
        out[ j + t ] = diff;
      }
      j1 += 2 * t;
    }
    if( reduce_add ) off_q = 1; else off_q <<= 1;
    t <<= 1;
    m >>= 1;
  }

  for( uint32_t j=0; j<(uint32_t)N; j++ )
    out[ j ] = fq_mul_shoup( out[ j ], 12265, S_PRIME_NINV );
}

/* ---------- hash-to-point: identical to falcon_ref_xkcp. */
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

/* For Hadamard product we need a fast Shoup multiply too.  The
 * pointwise product is between two arbitrary [0, Q) values where
 * neither has a precomputed s', so we precompute s' on the fly for one
 * of the operands.  In scalar this is just one extra multiply (almost
 * free since the load is in cache); for fairness with the AVX-512
 * Shoup variant the same convention applies. */
static inline fq_t
fq_mul_shoup_dyn( fq_t a, fq_t b ) {
  fq_t bp = (uint32_t)( ( (uint64_t)b << 32 ) / Q );
  return fq_mul_shoup( a, b, bp );
}

int
falcon4_xkcp_crypto_sign_open( uint8_t       * m,  size_t * mlen,
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

  fq_t h_ntt [ N ];
  fq_t s2_ntt[ N ];
  fq_t prod  [ N ];
  fq_t pmm   [ N ];
  ntt_fwd_scalar( h_ntt,  h  );
  ntt_fwd_scalar( s2_ntt, s2 );
  for( int i=0; i<N; i++ ) prod[ i ] = fq_mul_shoup_dyn( h_ntt[ i ], s2_ntt[ i ] );
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
