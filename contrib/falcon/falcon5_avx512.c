/* falcon5_avx512.c - AVX-512 Falcon-512 verification, merged forward
 *                    NTT, Barrett field multiplication.
 *
 * Same merged-forward-NTT structure as falcon3_avx512: the two
 * forward NTTs are run together on a 2N combined buffer with
 *   combined[2k]   = h[k]
 *   combined[2k+1] = s2[k]
 * so every pass operates at zmm width.  The only difference vs.
 * falcon3 is the modular multiplication: Barrett (this file) instead
 * of Shoup / Harvey precomputed-twiddle (falcon3).
 *
 * This isolates the merge benefit from the Shoup benefit:
 *
 *                | sequential 2 NTTs | merged combined buffer |
 *   Barrett mul  | falcon_avx512     | falcon5_avx512 (this)  |
 *   Shoup   mul  | falcon2_avx512    | falcon3_avx512         |
 *
 * Reading the table column-wise gives the merge effect at fixed mul
 * scheme; row-wise gives the mul effect at fixed merge structure.
 *
 * Public domain.
 */

#include "falcon_avx512_common.h"
#include "falcon_twiddle.h"

#include <stdint.h>

#if HAVE_AVX512

int falcon_ref_crypto_sign_open( uint8_t * m, size_t * mlen,
                                 uint8_t const * sm, size_t smlen,
                                 uint8_t const * pk );

/* ---------- Barrett field multiplication (zmm/ymm/sse). */

#define BARRETT_M 43687U
#define BARRETT_K 29

static inline __m512i
fq_mul_v( __m512i a, __m512i b ) {
  const __m512i Mv = _mm512_set1_epi32( (int)BARRETT_M );
  const __m512i Qv = _mm512_set1_epi32( Q );
  const __m512i mask_e = _mm512_set1_epi64( 0xFFFFFFFFLL );

  __m512i product = _mm512_mullo_epi32( a, b );
  __m512i wide_e = _mm512_mul_epu32( product, Mv );
  __m512i qest_e = _mm512_srli_epi64( wide_e, BARRETT_K );
  __m512i prod_o = _mm512_srli_epi64( product, 32 );
  __m512i wide_o = _mm512_mul_epu32( prod_o, Mv );
  __m512i qest_o = _mm512_srli_epi64( wide_o, BARRETT_K );
  __m512i qest_o_s = _mm512_slli_epi64( qest_o, 32 );
  __m512i qest = _mm512_or_si512( _mm512_and_si512( qest_e, mask_e ), qest_o_s );
  __m512i r = _mm512_sub_epi32( product, _mm512_mullo_epi32( qest, Qv ) );
  __m512i d    = _mm512_sub_epi32( r, Qv );
  __m512i sign = _mm512_srai_epi32( d, 31 );
  return _mm512_add_epi32( d, _mm512_and_si512( Qv, sign ) );
}

static inline __m256i
fq_mul_avx2( __m256i a, __m256i b ) {
  const __m256i Mv = _mm256_set1_epi32( (int)BARRETT_M );
  const __m256i Qv = _mm256_set1_epi32( Q );
  const __m256i mask_e = _mm256_set1_epi64x( 0xFFFFFFFFLL );

  __m256i product = _mm256_mullo_epi32( a, b );
  __m256i wide_e = _mm256_mul_epu32( product, Mv );
  __m256i qest_e = _mm256_srli_epi64( wide_e, BARRETT_K );
  __m256i prod_o = _mm256_srli_epi64( product, 32 );
  __m256i wide_o = _mm256_mul_epu32( prod_o, Mv );
  __m256i qest_o = _mm256_srli_epi64( wide_o, BARRETT_K );
  __m256i qest_o_s = _mm256_slli_epi64( qest_o, 32 );
  __m256i qest = _mm256_or_si256( _mm256_and_si256( qest_e, mask_e ), qest_o_s );
  __m256i r = _mm256_sub_epi32( product, _mm256_mullo_epi32( qest, Qv ) );
  __m256i d    = _mm256_sub_epi32( r, Qv );
  __m256i sign = _mm256_srai_epi32( d, 31 );
  return _mm256_add_epi32( d, _mm256_and_si256( Qv, sign ) );
}

static inline __m128i
fq_mul_sse( __m128i a, __m128i b ) {
  const __m128i Mv = _mm_set1_epi32( (int)BARRETT_M );
  const __m128i Qv = _mm_set1_epi32( Q );
  const __m128i mask_e = _mm_set1_epi64x( 0xFFFFFFFFLL );

  __m128i product = _mm_mullo_epi32( a, b );
  __m128i wide_e = _mm_mul_epu32( product, Mv );
  __m128i qest_e = _mm_srli_epi64( wide_e, BARRETT_K );
  __m128i prod_o = _mm_srli_epi64( product, 32 );
  __m128i wide_o = _mm_mul_epu32( prod_o, Mv );
  __m128i qest_o = _mm_srli_epi64( wide_o, BARRETT_K );
  __m128i qest_o_s = _mm_slli_epi64( qest_o, 32 );
  __m128i qest = _mm_or_si128( _mm_and_si128( qest_e, mask_e ), qest_o_s );
  __m128i r = _mm_sub_epi32( product, _mm_mullo_epi32( qest, Qv ) );
  __m128i d    = _mm_sub_epi32( r, Qv );
  __m128i sign = _mm_srai_epi32( d, 31 );
  return _mm_add_epi32( d, _mm_and_si128( Qv, sign ) );
}

/* ---------- Merged forward NTT (Barrett mul, combined-buffer layout).
 *
 * Identical structure to falcon3's `ntt_fwd2_avx512`; only the field
 * multiplication and the final reduction-by-1 step are Barrett. */

static void
ntt_fwd2_avx512( falcon_fq_t * h_out, falcon_fq_t const * h_in,
                 falcon_fq_t * s_out, falcon_fq_t const * s_in ) {
  falcon_fq_t combined[ 2 * N ] __attribute__((aligned(64)));

  /* Interleave h_in and s_in into combined. */
  __m512i idx_lo32 = _mm512_setr_epi32(
      0, 16+0, 1, 16+1, 2, 16+2, 3, 16+3,
      4, 16+4, 5, 16+5, 6, 16+6, 7, 16+7 );
  __m512i idx_hi32 = _mm512_setr_epi32(
      8, 16+8, 9, 16+9, 10, 16+10, 11, 16+11,
      12, 16+12, 13, 16+13, 14, 16+14, 15, 16+15 );
  for( uint32_t k=0; k<(uint32_t)N; k+=16 ) {
    __m512i hv = _mm512_loadu_si512( (void const *)( h_in + k ) );
    __m512i sv = _mm512_loadu_si512( (void const *)( s_in + k ) );
    _mm512_storeu_si512( (void *)( combined + 2*k     ),
        _mm512_permutex2var_epi32( hv, idx_lo32, sv ) );
    _mm512_storeu_si512( (void *)( combined + 2*k + 16 ),
        _mm512_permutex2var_epi32( hv, idx_hi32, sv ) );
  }

  const __m512i Qv512 = _mm512_set1_epi32( Q );

  uint32_t t = N;
  uint32_t m = 1;
  while( m < (uint32_t)N ) {
    t >>= 1;

    if( t >= 8 ) {
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t base = 4 * i * t;
        __m512i sv = _mm512_set1_epi32( (int)falcon_psi_positive[ m + i ] );
        for( uint32_t j=0; j<2*t; j+=16 ) {
          __m512i u = _mm512_loadu_si512( (void const *)( combined + base + j ) );
          __m512i v = fq_mul_v(
              _mm512_loadu_si512( (void const *)( combined + base + j + 2*t ) ), sv );
          _mm512_storeu_si512( (void *)( combined + base + j     ),
              _mm512_add_epi32( u, v ) );
          _mm512_storeu_si512( (void *)( combined + base + j + 2*t ),
              _mm512_add_epi32( _mm512_sub_epi32( u, v ), Qv512 ) );
        }
      }
    } else if( t == 4 ) {
      for( uint32_t i=0; i<m; i+=2 ) {
        uint32_t base = 4 * i * t;
        __m256i ui  = _mm256_loadu_si256( (__m256i const *)( combined + base      ) );
        __m256i vi  = _mm256_loadu_si256( (__m256i const *)( combined + base +  8 ) );
        __m256i uip = _mm256_loadu_si256( (__m256i const *)( combined + base + 16 ) );
        __m256i vip = _mm256_loadu_si256( (__m256i const *)( combined + base + 24 ) );
        __m512i u = _mm512_inserti64x4( _mm512_castsi256_si512( ui ), uip, 1 );
        __m512i v = _mm512_inserti64x4( _mm512_castsi256_si512( vi ), vip, 1 );

        __m512i sv = _mm512_inserti64x4(
            _mm512_castsi256_si512( _mm256_set1_epi32( (int)falcon_psi_positive[ m + i + 0 ] ) ),
            _mm256_set1_epi32( (int)falcon_psi_positive[ m + i + 1 ] ), 1 );

        v = fq_mul_v( v, sv );
        __m512i u_new = _mm512_add_epi32( u, v );
        __m512i v_new = _mm512_add_epi32( _mm512_sub_epi32( u, v ), Qv512 );
        _mm256_storeu_si256( (__m256i *)( combined + base      ), _mm512_castsi512_si256( u_new ) );
        _mm256_storeu_si256( (__m256i *)( combined + base +  8 ), _mm512_castsi512_si256( v_new ) );
        _mm256_storeu_si256( (__m256i *)( combined + base + 16 ), _mm512_extracti64x4_epi64( u_new, 1 ) );
        _mm256_storeu_si256( (__m256i *)( combined + base + 24 ), _mm512_extracti64x4_epi64( v_new, 1 ) );
      }
    } else if( t == 2 ) {
      __m512i idx_u = _mm512_setr_epi32(
          0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27 );
      __m512i idx_v = _mm512_setr_epi32(
          4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31 );
      __m512i idx_pack0 = _mm512_setr_epi32(
          0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23 );
      __m512i idx_pack1 = _mm512_setr_epi32(
          8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31 );
      for( uint32_t i=0; i<m; i+=4 ) {
        uint32_t base = 4 * i * t;
        __m512i raw0 = _mm512_loadu_si512( (void const *)( combined + base      ) );
        __m512i raw1 = _mm512_loadu_si512( (void const *)( combined + base + 16 ) );
        __m512i u = _mm512_permutex2var_epi32( raw0, idx_u, raw1 );
        __m512i v = _mm512_permutex2var_epi32( raw0, idx_v, raw1 );

        falcon_fq_t const * tw = falcon_psi_positive + m + i;
        __m512i sv = _mm512_setr_epi32(
            (int)tw[0], (int)tw[0], (int)tw[0], (int)tw[0],
            (int)tw[1], (int)tw[1], (int)tw[1], (int)tw[1],
            (int)tw[2], (int)tw[2], (int)tw[2], (int)tw[2],
            (int)tw[3], (int)tw[3], (int)tw[3], (int)tw[3] );

        v = fq_mul_v( v, sv );
        __m512i u_new = _mm512_add_epi32( u, v );
        __m512i v_new = _mm512_add_epi32( _mm512_sub_epi32( u, v ), Qv512 );
        _mm512_storeu_si512( (void *)( combined + base      ),
            _mm512_permutex2var_epi32( u_new, idx_pack0, v_new ) );
        _mm512_storeu_si512( (void *)( combined + base + 16 ),
            _mm512_permutex2var_epi32( u_new, idx_pack1, v_new ) );
      }
    } else { /* t == 1 */
      __m512i idx_u = _mm512_setr_epi32(
          0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29 );
      __m512i idx_v = _mm512_setr_epi32(
          2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31 );
      __m512i idx_pack0 = _mm512_setr_epi32(
          0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23 );
      __m512i idx_pack1 = _mm512_setr_epi32(
          8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31 );
      __m512i idx_dup = _mm512_setr_epi32(
          0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7 );
      for( uint32_t i=0; i<m; i+=8 ) {
        uint32_t base = 4 * i * t;
        __m512i raw0 = _mm512_loadu_si512( (void const *)( combined + base      ) );
        __m512i raw1 = _mm512_loadu_si512( (void const *)( combined + base + 16 ) );
        __m512i u = _mm512_permutex2var_epi32( raw0, idx_u, raw1 );
        __m512i v = _mm512_permutex2var_epi32( raw0, idx_v, raw1 );

        __m256i tw256 = _mm256_loadu_si256(
            (__m256i const *)( falcon_psi_positive + m + i ) );
        __m512i sv = _mm512_permutexvar_epi32( idx_dup,
                          _mm512_castsi256_si512( tw256 ) );

        v = fq_mul_v( v, sv );
        __m512i u_new = _mm512_add_epi32( u, v );
        __m512i v_new = _mm512_add_epi32( _mm512_sub_epi32( u, v ), Qv512 );
        _mm512_storeu_si512( (void *)( combined + base      ),
            _mm512_permutex2var_epi32( u_new, idx_pack0, v_new ) );
        _mm512_storeu_si512( (void *)( combined + base + 16 ),
            _mm512_permutex2var_epi32( u_new, idx_pack1, v_new ) );
      }
    }

    m <<= 1;
  }

  /* Final reduction by 1: Barrett mul-by-1 normalises lazy values. */
  __m512i one = _mm512_set1_epi32( 1 );
  for( uint32_t j=0; j<2*(uint32_t)N; j+=16 ) {
    __m512i x = _mm512_loadu_si512( (void const *)( combined + j ) );
    _mm512_storeu_si512( (void *)( combined + j ), fq_mul_v( x, one ) );
  }

  /* Deinterleave. */
  __m512i idx_h = _mm512_setr_epi32(
      0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30 );
  __m512i idx_s = _mm512_setr_epi32(
      1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31 );
  for( uint32_t k=0; k<(uint32_t)N; k+=16 ) {
    __m512i raw0 = _mm512_loadu_si512( (void const *)( combined + 2*k      ) );
    __m512i raw1 = _mm512_loadu_si512( (void const *)( combined + 2*k + 16 ) );
    _mm512_storeu_si512( (void *)( h_out + k ),
        _mm512_permutex2var_epi32( raw0, idx_h, raw1 ) );
    _mm512_storeu_si512( (void *)( s_out + k ),
        _mm512_permutex2var_epi32( raw0, idx_s, raw1 ) );
  }
}

/* ---------- Inverse NTT (Barrett, single instance, copied from
 * falcon_avx512.c). */

static void
ntt_inv_avx512( falcon_fq_t * out, falcon_fq_t const * in ) {
  memcpy( out, in, sizeof(falcon_fq_t) * N );

  const __m512i one512 = _mm512_set1_epi32( 1 );
  const __m256i one256 = _mm256_set1_epi32( 1 );
  const __m128i one128 = _mm_set1_epi32( 1 );

  uint32_t t     = 1;
  uint32_t m     = N;
  uint32_t off_q = 1;
  while( m > 1 ) {
    uint32_t h          = m >> 1;
    uint32_t off        = off_q * Q;
    int      reduce_add = ( off_q >= 8 );

    if( t >= 16 ) {
      __m512i offv = _mm512_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i++ ) {
        __m512i sv = _mm512_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        for( uint32_t j=j1; j<j1+t; j+=16 ) {
          __m512i u    = _mm512_loadu_si512( (void const *)( out + j ) );
          __m512i v    = _mm512_loadu_si512( (void const *)( out + j + t ) );
          __m512i sum  = _mm512_add_epi32( u, v );
          __m512i diff = fq_mul_v(
              _mm512_add_epi32( _mm512_sub_epi32( u, v ), offv ), sv );
          _mm512_storeu_si512( (void *)( out + j     ),
                               reduce_add ? fq_mul_v( sum, one512 ) : sum );
          _mm512_storeu_si512( (void *)( out + j + t ), diff );
        }
        j1 += 2 * t;
      }
    } else if( t == 8 ) {
      __m256i offv = _mm256_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i++ ) {
        __m256i sv = _mm256_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        __m256i u  = _mm256_loadu_si256( (void const *)( out + j1 ) );
        __m256i v  = _mm256_loadu_si256( (void const *)( out + j1 + t ) );
        __m256i sum  = _mm256_add_epi32( u, v );
        __m256i diff = fq_mul_avx2( _mm256_add_epi32( _mm256_sub_epi32( u, v ), offv ), sv );
        _mm256_storeu_si256( (void *)( out + j1     ),
                             reduce_add ? fq_mul_avx2( sum, one256 ) : sum );
        _mm256_storeu_si256( (void *)( out + j1 + t ), diff );
        j1 += 2 * t;
      }
    } else if( t == 4 ) {
      __m128i offv = _mm_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i++ ) {
        __m128i sv = _mm_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        __m128i u  = _mm_loadu_si128( (void const *)( out + j1     ) );
        __m128i v  = _mm_loadu_si128( (void const *)( out + j1 + 4 ) );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv );
        _mm_storeu_si128( (void *)( out + j1     ),
                          reduce_add ? fq_mul_sse( sum, one128 ) : sum );
        _mm_storeu_si128( (void *)( out + j1 + 4 ), diff );
        j1 += 8;
      }
    } else if( t == 2 ) {
      __m128i offv = _mm_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i+=2 ) {
        __m128i d0 = _mm_loadu_si128( (void const *)( out + j1     ) );
        __m128i d1 = _mm_loadu_si128( (void const *)( out + j1 + 4 ) );
        __m128i u  = _mm_unpacklo_epi64( d0, d1 );
        __m128i v  = _mm_unpackhi_epi64( d0, d1 );
        uint32_t s0 = falcon_psi_negative[ h + i     ];
        uint32_t s1 = falcon_psi_negative[ h + i + 1 ];
        __m128i sv = _mm_setr_epi32( (int)s0, (int)s0, (int)s1, (int)s1 );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv );
        if( reduce_add ) sum = fq_mul_sse( sum, one128 );
        __m128i o0 = _mm_unpacklo_epi64( sum, diff );
        __m128i o1 = _mm_unpackhi_epi64( sum, diff );
        _mm_storeu_si128( (void *)( out + j1     ), o0 );
        _mm_storeu_si128( (void *)( out + j1 + 4 ), o1 );
        j1 += 8;
      }
    } else { /* t == 1 */
      __m128i offv = _mm_set1_epi32( (int)off );
      for( uint32_t i=0; i<h; i+=4 ) {
        __m128i d0  = _mm_loadu_si128( (void const *)( out + 2*i     ) );
        __m128i d1  = _mm_loadu_si128( (void const *)( out + 2*i + 4 ) );
        __m128i d0s = _mm_shuffle_epi32( d0, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        __m128i d1s = _mm_shuffle_epi32( d1, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        __m128i u   = _mm_unpacklo_epi64( d0s, d1s );
        __m128i v   = _mm_unpackhi_epi64( d0s, d1s );
        __m128i sv  = _mm_loadu_si128( (void const *)( falcon_psi_negative + h + i ) );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv );
        if( reduce_add ) sum = fq_mul_sse( sum, one128 );
        __m128i o0 = _mm_unpacklo_epi64( sum, diff );
        __m128i o1 = _mm_unpackhi_epi64( sum, diff );
        o0 = _mm_shuffle_epi32( o0, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        o1 = _mm_shuffle_epi32( o1, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        _mm_storeu_si128( (void *)( out + 2*i     ), o0 );
        _mm_storeu_si128( (void *)( out + 2*i + 4 ), o1 );
      }
    }
    if( reduce_add ) off_q = 1; else off_q <<= 1;
    t <<= 1;
    m >>= 1;
  }

  __m512i n_inv = _mm512_set1_epi32( 12265 );
  for( uint32_t j=0; j<(uint32_t)N; j+=16 ) {
    __m512i x = _mm512_loadu_si512( (void const *)( out + j ) );
    _mm512_storeu_si512( (void *)( out + j ), fq_mul_v( x, n_inv ) );
  }
}

int
falcon5_avx512_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                 uint8_t const * sm, size_t   smlen,
                                 uint8_t const * pk ) {
  enum { NONCELEN = 40, PK_HEADER = 0x09, SIG_HEADER = 0x29 };

  if( UNLIKELY( pk[ 0 ] != PK_HEADER ) ) return -1;
  if( UNLIKELY( smlen < 2 + NONCELEN + 1 ) ) return -1;

  size_t sig_field_len = ( (size_t)sm[ 0 ] << 8 ) | (size_t)sm[ 1 ];
  if( UNLIKELY( sig_field_len < 1 ) ) return -1;
  if( UNLIKELY( sig_field_len > smlen - 2 - NONCELEN ) ) return -1;

  size_t          msg_len = smlen - 2 - NONCELEN - sig_field_len;
  uint8_t const * nonce   = sm + 2;
  uint8_t const * msg     = sm + 2 + NONCELEN;
  uint8_t const * esig    = sm + 2 + NONCELEN + msg_len;

  if( UNLIKELY( esig[ 0 ] != SIG_HEADER ) ) return -1;

  falcon_pubkey_t    pubk[1];
  falcon_signature_t sig [1];
  if( UNLIKELY( fa512_parse_pk(      pubk,    pk + 1                  ) ) ) return -1;
  if( UNLIKELY( fa512_parse_comp_s2( sig->s2, esig + 1, sig_field_len-1 ) ) ) return -1;

  falcon_fq_t c[ N + 16 ] __attribute__((aligned(64)));
  fa512_hash_to_point( c, nonce, msg, msg_len );

  falcon_fq_t s2_ntt[ N ] __attribute__((aligned(64)));
  falcon_fq_t h_ntt [ N ] __attribute__((aligned(64)));
  falcon_fq_t prod  [ N ] __attribute__((aligned(64)));

  ntt_fwd2_avx512( h_ntt, pubk->h, s2_ntt, sig->s2 );

  /* Hadamard: same Barrett mul as the NTT. */
  for( int i=0; i<N; i+=16 ) {
    __m512i a = _mm512_loadu_si512( (void const *)( s2_ntt + i ) );
    __m512i b = _mm512_loadu_si512( (void const *)( h_ntt  + i ) );
    _mm512_storeu_si512( (void *)( prod + i ), fq_mul_v( a, b ) );
  }

  falcon_fq_t pmm[ N ] __attribute__((aligned(64)));
  ntt_inv_avx512( pmm, prod );

  if( !fa512_norm_check_ok( c, pmm, sig ) ) return -1;

  if( m && msg_len ) memmove( m, msg, msg_len );
  if( mlen ) *mlen = msg_len;
  return 0;
}

#else /* !HAVE_AVX512 */

int
falcon5_avx512_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                 uint8_t const * sm, size_t   smlen,
                                 uint8_t const * pk ) {
  return falcon_ref_crypto_sign_open( m, mlen, sm, smlen, pk );
}

#endif
