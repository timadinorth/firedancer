/* falcon3_avx512.c - AVX-512 Falcon-512 verification, "merged forward
 *                    NTT" variant.
 *
 * Same NTT algorithm as `falcon2_avx512` (Shoup mul, lazy reduction),
 * but the two forward NTTs (NTT(h) and NTT(s2)) are merged into a
 * single function `ntt_fwd2_avx512`.  Both forward NTTs are
 * data-independent and share the same twiddle table, so we can pack
 * one h-coefficient and one s2-coefficient side-by-side in each
 * 64-bit slot of a 32-bit-lane zmm.  Every pass of the merged NTT
 * therefore runs at full zmm width, including the small-stride
 * passes (t=4, 2, 1) that the un-merged code drops to SSE for.
 *
 * Theoretical bound (port-5-bound, Skylake-SP/CSL):
 *
 *   un-merged: 5*(256/16) + 1*(256/8) + 3*(256/4) cycles per NTT
 *            = 5*16 + 32 + 3*64 = 304 mul-cycles / NTT, 608 / pair.
 *      In Shoup the per-butterfly mul count is 4, so multiply by 4:
 *      1216 / NTT, 2432 / pair.
 *
 *   merged:    9 passes * 512 butterflies / 16 lanes = 288 mul-vec
 *              ops * 4 muls/vec = 1152 cycles / pair.
 *
 *   Speedup of the forward-NTT pair: 2432 / 1152 ≈ 2.11x.
 *
 * The actual wall-clock saving is smaller than this bound because of
 * (a) the interleave/deinterleave at start/end of the merged NTT,
 * (b) shuffles needed to broadcast multiple twiddles to lane groups
 *     at the small-stride passes, and (c) the inverse NTT and SHAKE
 * are unchanged.
 *
 * Inverse NTT, parsing, hash-to-point, Hadamard, and norm check are
 * all unchanged from `falcon2_avx512`.  Only the forward NTT pair
 * differs.
 *
 * Public domain.
 */

#include "falcon_avx512_common.h"
#include "falcon_twiddle.h"

#if HAVE_AVX512

int falcon_ref_crypto_sign_open( uint8_t * m, size_t * mlen,
                                 uint8_t const * sm, size_t smlen,
                                 uint8_t const * pk );

/* ---------- Shoup precomputed multiplier tables. */

static falcon_fq_t s_prime_pos[ N ] __attribute__((aligned(64)));
static falcon_fq_t s_prime_neg[ N ] __attribute__((aligned(64)));

#define S_PRIME_ONE   ( (uint32_t)( ( (uint64_t)1     << 32 ) / Q ) )
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

/* ---------- Shoup field multiplication.  Same as falcon2_avx512. */

static inline __m512i
fq_mul_shoup_v( __m512i v, __m512i s, __m512i s_prime ) {
  const __m512i Qv      = _mm512_set1_epi32( Q );
  const __m512i mask_lo = _mm512_set1_epi64( 0x00000000FFFFFFFFLL );

  __m512i wide_e = _mm512_mul_epu32( v, s_prime );
  __m512i v_o    = _mm512_srli_epi64( v,       32 );
  __m512i sp_o   = _mm512_srli_epi64( s_prime, 32 );
  __m512i wide_o = _mm512_mul_epu32( v_o, sp_o );

  __m512i q_hat_e = _mm512_srli_epi64( wide_e, 32 );
  __m512i q_hat_o = _mm512_andnot_si512( mask_lo, wide_o );
  __m512i q_hat   = _mm512_or_si512( q_hat_e, q_hat_o );

  __m512i vs  = _mm512_mullo_epi32( v, s );
  __m512i qq  = _mm512_mullo_epi32( q_hat, Qv );
  __m512i r   = _mm512_sub_epi32(   vs, qq );

  __m512i d    = _mm512_sub_epi32( r, Qv );
  __m512i sign = _mm512_srai_epi32( d, 31 );
  return _mm512_add_epi32( d, _mm512_and_si512( Qv, sign ) );
}

static inline __m256i
fq_mul_shoup_avx2( __m256i v, __m256i s, __m256i s_prime ) {
  const __m256i Qv      = _mm256_set1_epi32( Q );
  const __m256i mask_lo = _mm256_set1_epi64x( 0x00000000FFFFFFFFLL );
  __m256i wide_e = _mm256_mul_epu32( v, s_prime );
  __m256i v_o    = _mm256_srli_epi64( v,       32 );
  __m256i sp_o   = _mm256_srli_epi64( s_prime, 32 );
  __m256i wide_o = _mm256_mul_epu32( v_o, sp_o );
  __m256i q_hat_e = _mm256_srli_epi64( wide_e, 32 );
  __m256i q_hat_o = _mm256_andnot_si256( mask_lo, wide_o );
  __m256i q_hat   = _mm256_or_si256( q_hat_e, q_hat_o );
  __m256i vs  = _mm256_mullo_epi32( v, s );
  __m256i qq  = _mm256_mullo_epi32( q_hat, Qv );
  __m256i r   = _mm256_sub_epi32(   vs, qq );
  __m256i d    = _mm256_sub_epi32( r, Qv );
  __m256i sign = _mm256_srai_epi32( d, 31 );
  return _mm256_add_epi32( d, _mm256_and_si256( Qv, sign ) );
}

static inline __m128i
fq_mul_shoup_sse( __m128i v, __m128i s, __m128i s_prime ) {
  const __m128i Qv      = _mm_set1_epi32( Q );
  const __m128i mask_lo = _mm_set1_epi64x( 0x00000000FFFFFFFFLL );
  __m128i wide_e = _mm_mul_epu32( v, s_prime );
  __m128i v_o    = _mm_srli_epi64( v,       32 );
  __m128i sp_o   = _mm_srli_epi64( s_prime, 32 );
  __m128i wide_o = _mm_mul_epu32( v_o, sp_o );
  __m128i q_hat_e = _mm_srli_epi64( wide_e, 32 );
  __m128i q_hat_o = _mm_andnot_si128( mask_lo, wide_o );
  __m128i q_hat   = _mm_or_si128( q_hat_e, q_hat_o );
  __m128i vs  = _mm_mullo_epi32( v, s );
  __m128i qq  = _mm_mullo_epi32( q_hat, Qv );
  __m128i r   = _mm_sub_epi32(   vs, qq );
  __m128i d    = _mm_sub_epi32( r, Qv );
  __m128i sign = _mm_srai_epi32( d, 31 );
  return _mm_add_epi32( d, _mm_and_si128( Qv, sign ) );
}

/* ---------- Merged forward NTT.
 *
 * Combined memory layout:  combined[2k]   = h[k]
 *                          combined[2k+1] = s2[k]
 *
 * Under this layout, an original-index butterfly between (j, j+t) for
 * h becomes a butterfly between combined[2j] and combined[2(j+t)],
 * and the corresponding s2-butterfly is between combined[2j+1] and
 * combined[2(j+t)+1].  Both butterflies use the same twiddle, so a
 * single zmm op naturally processes 8 (h, s2) pair-butterflies = 16
 * scalar lanes.
 *
 * For an original stride t, the (u, v) offset in combined is 2t scalar
 * elements.  When 2t >= 16, every zmm-wide vector is a contiguous
 * slice of u (or v) values from a single butterfly group, with one
 * shared twiddle.  When 2t < 16 (i.e. t in {4, 2, 1}), one zmm spans
 * multiple butterfly groups with distinct twiddles, and we build the
 * twiddle vector at the top of the loop. */

static void
ntt_fwd2_avx512( falcon_fq_t       * h_out, falcon_fq_t const * h_in,
                 falcon_fq_t       * s_out, falcon_fq_t const * s_in ) {
  falcon_fq_t combined[ 2*N ] __attribute__((aligned(64)));

  /* (1) Interleave h and s2 into combined, 32 elements per outer iter
   *     (16 from h, 16 from s2). */
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

  /* (2) Run all 9 passes on the combined buffer. */
  uint32_t t = N;
  uint32_t m = 1;
  while( m < (uint32_t)N ) {
    t >>= 1;

    if( t >= 8 ) {
      /* 2*t >= 16: every zmm-wide slice belongs to one butterfly
       * group.  One shared twiddle per outer iteration. */
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t base = 4 * i * t;
        __m512i sv  = _mm512_set1_epi32( (int)falcon_psi_positive[ m + i ] );
        __m512i spv = _mm512_set1_epi32( (int)s_prime_pos        [ m + i ] );
        for( uint32_t j=0; j<2*t; j+=16 ) {
          __m512i u = _mm512_loadu_si512( (void const *)( combined + base + j ) );
          __m512i v = fq_mul_shoup_v(
              _mm512_loadu_si512( (void const *)( combined + base + j + 2*t ) ),
              sv, spv );
          _mm512_storeu_si512( (void *)( combined + base + j     ),
              _mm512_add_epi32( u, v ) );
          _mm512_storeu_si512( (void *)( combined + base + j + 2*t ),
              _mm512_add_epi32( _mm512_sub_epi32( u, v ), Qv512 ) );
        }
      }
    } else if( t == 4 ) {
      /* 2*t = 8 scalars per group-half.  Pack 2 groups (i, i+1) per
       * zmm: low 8 lanes = group i, high 8 lanes = group i+1. */
      for( uint32_t i=0; i<m; i+=2 ) {
        uint32_t base = 4 * i * t;  /* = 16 i */
        /* Memory layout in combined[base..base+31]:
         *   [u_i (8 sc), v_i (8 sc), u_{i+1} (8 sc), v_{i+1} (8 sc)] */
        __m256i ui  = _mm256_loadu_si256( (__m256i const *)( combined + base      ) );
        __m256i vi  = _mm256_loadu_si256( (__m256i const *)( combined + base +  8 ) );
        __m256i uip = _mm256_loadu_si256( (__m256i const *)( combined + base + 16 ) );
        __m256i vip = _mm256_loadu_si256( (__m256i const *)( combined + base + 24 ) );
        __m512i u = _mm512_inserti64x4( _mm512_castsi256_si512( ui ), uip, 1 );
        __m512i v = _mm512_inserti64x4( _mm512_castsi256_si512( vi ), vip, 1 );

        __m512i sv  = _mm512_inserti64x4(
            _mm512_castsi256_si512( _mm256_set1_epi32( (int)falcon_psi_positive[ m + i + 0 ] ) ),
            _mm256_set1_epi32( (int)falcon_psi_positive[ m + i + 1 ] ), 1 );
        __m512i spv = _mm512_inserti64x4(
            _mm512_castsi256_si512( _mm256_set1_epi32( (int)s_prime_pos[ m + i + 0 ] ) ),
            _mm256_set1_epi32( (int)s_prime_pos[ m + i + 1 ] ), 1 );

        v = fq_mul_shoup_v( v, sv, spv );
        __m512i u_new = _mm512_add_epi32( u, v );
        __m512i v_new = _mm512_add_epi32( _mm512_sub_epi32( u, v ), Qv512 );

        _mm256_storeu_si256( (__m256i *)( combined + base      ), _mm512_castsi512_si256( u_new ) );
        _mm256_storeu_si256( (__m256i *)( combined + base +  8 ), _mm512_castsi512_si256( v_new ) );
        _mm256_storeu_si256( (__m256i *)( combined + base + 16 ), _mm512_extracti64x4_epi64( u_new, 1 ) );
        _mm256_storeu_si256( (__m256i *)( combined + base + 24 ), _mm512_extracti64x4_epi64( v_new, 1 ) );
      }
    } else if( t == 2 ) {
      /* 2*t = 4 scalars per group-half.  Pack 4 groups per zmm.  Use
       * vpermi2d to gather u and v halves. */
      __m512i idx_u = _mm512_setr_epi32(
          0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27 );
      __m512i idx_v = _mm512_setr_epi32(
          4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31 );
      __m512i idx_pack0 = _mm512_setr_epi32(
          0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23 );
      __m512i idx_pack1 = _mm512_setr_epi32(
          8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31 );

      for( uint32_t i=0; i<m; i+=4 ) {
        uint32_t base = 4 * i * t;  /* = 8 i */
        __m512i raw0 = _mm512_loadu_si512( (void const *)( combined + base      ) );
        __m512i raw1 = _mm512_loadu_si512( (void const *)( combined + base + 16 ) );
        __m512i u = _mm512_permutex2var_epi32( raw0, idx_u, raw1 );
        __m512i v = _mm512_permutex2var_epi32( raw0, idx_v, raw1 );

        falcon_fq_t const * tw = falcon_psi_positive + m + i;
        falcon_fq_t const * tp = s_prime_pos         + m + i;
        __m512i sv  = _mm512_setr_epi32(
            (int)tw[0], (int)tw[0], (int)tw[0], (int)tw[0],
            (int)tw[1], (int)tw[1], (int)tw[1], (int)tw[1],
            (int)tw[2], (int)tw[2], (int)tw[2], (int)tw[2],
            (int)tw[3], (int)tw[3], (int)tw[3], (int)tw[3] );
        __m512i spv = _mm512_setr_epi32(
            (int)tp[0], (int)tp[0], (int)tp[0], (int)tp[0],
            (int)tp[1], (int)tp[1], (int)tp[1], (int)tp[1],
            (int)tp[2], (int)tp[2], (int)tp[2], (int)tp[2],
            (int)tp[3], (int)tp[3], (int)tp[3], (int)tp[3] );

        v = fq_mul_shoup_v( v, sv, spv );
        __m512i u_new = _mm512_add_epi32( u, v );
        __m512i v_new = _mm512_add_epi32( _mm512_sub_epi32( u, v ), Qv512 );

        _mm512_storeu_si512( (void *)( combined + base      ),
            _mm512_permutex2var_epi32( u_new, idx_pack0, v_new ) );
        _mm512_storeu_si512( (void *)( combined + base + 16 ),
            _mm512_permutex2var_epi32( u_new, idx_pack1, v_new ) );
      }
    } else { /* t == 1 */
      /* 2*t = 2 scalars per group-half.  Pack 8 groups per zmm. */
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
        uint32_t base = 4 * i * t;  /* = 4 i */
        __m512i raw0 = _mm512_loadu_si512( (void const *)( combined + base      ) );
        __m512i raw1 = _mm512_loadu_si512( (void const *)( combined + base + 16 ) );
        __m512i u = _mm512_permutex2var_epi32( raw0, idx_u, raw1 );
        __m512i v = _mm512_permutex2var_epi32( raw0, idx_v, raw1 );

        __m256i tw256 = _mm256_loadu_si256(
            (__m256i const *)( falcon_psi_positive + m + i ) );
        __m256i tp256 = _mm256_loadu_si256(
            (__m256i const *)( s_prime_pos         + m + i ) );
        __m512i sv  = _mm512_permutexvar_epi32( idx_dup,
                          _mm512_castsi256_si512( tw256 ) );
        __m512i spv = _mm512_permutexvar_epi32( idx_dup,
                          _mm512_castsi256_si512( tp256 ) );

        v = fq_mul_shoup_v( v, sv, spv );
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

  /* (3) Final reduction by 1: multiply every combined element by 1 to
   *     normalise lazy values to [0, Q). */
  __m512i one  = _mm512_set1_epi32( 1 );
  __m512i pone = _mm512_set1_epi32( (int)S_PRIME_ONE );
  for( uint32_t j=0; j<2*(uint32_t)N; j+=16 ) {
    __m512i x = _mm512_loadu_si512( (void const *)( combined + j ) );
    _mm512_storeu_si512( (void *)( combined + j ),
        fq_mul_shoup_v( x, one, pone ) );
  }

  /* (4) Deinterleave back into h_out and s_out. */
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

/* ---------- Inverse NTT (single instance, unmodified from
 * falcon2_avx512.c).  We only have one inverse NTT per verification,
 * so there's nothing to merge it with. */

static void
ntt_inv_avx512( falcon_fq_t * out, falcon_fq_t const * in ) {
  memcpy( out, in, sizeof(falcon_fq_t) * N );

  const __m512i one512  = _mm512_set1_epi32( 1 );
  const __m256i one256  = _mm256_set1_epi32( 1 );
  const __m128i one128  = _mm_set1_epi32( 1 );
  const __m512i pone512 = _mm512_set1_epi32( (int)S_PRIME_ONE );
  const __m256i pone256 = _mm256_set1_epi32( (int)S_PRIME_ONE );
  const __m128i pone128 = _mm_set1_epi32(    (int)S_PRIME_ONE );

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
        __m512i sv  = _mm512_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        __m512i spv = _mm512_set1_epi32( (int)s_prime_neg        [ h + i ] );
        for( uint32_t j=j1; j<j1+t; j+=16 ) {
          __m512i u    = _mm512_loadu_si512( (void const *)( out + j ) );
          __m512i v    = _mm512_loadu_si512( (void const *)( out + j + t ) );
          __m512i sum  = _mm512_add_epi32( u, v );
          __m512i diff = fq_mul_shoup_v(
              _mm512_add_epi32( _mm512_sub_epi32( u, v ), offv ), sv, spv );
          _mm512_storeu_si512( (void *)( out + j     ),
                               reduce_add ? fq_mul_shoup_v( sum, one512, pone512 ) : sum );
          _mm512_storeu_si512( (void *)( out + j + t ), diff );
        }
        j1 += 2 * t;
      }
    } else if( t == 8 ) {
      __m256i offv = _mm256_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i++ ) {
        __m256i sv  = _mm256_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        __m256i spv = _mm256_set1_epi32( (int)s_prime_neg        [ h + i ] );
        __m256i u    = _mm256_loadu_si256( (void const *)( out + j1 ) );
        __m256i v    = _mm256_loadu_si256( (void const *)( out + j1 + t ) );
        __m256i sum  = _mm256_add_epi32( u, v );
        __m256i diff = fq_mul_shoup_avx2( _mm256_add_epi32( _mm256_sub_epi32( u, v ), offv ), sv, spv );
        _mm256_storeu_si256( (void *)( out + j1     ),
                             reduce_add ? fq_mul_shoup_avx2( sum, one256, pone256 ) : sum );
        _mm256_storeu_si256( (void *)( out + j1 + t ), diff );
        j1 += 2 * t;
      }
    } else if( t == 4 ) {
      __m128i offv = _mm_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i++ ) {
        __m128i sv  = _mm_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        __m128i spv = _mm_set1_epi32( (int)s_prime_neg        [ h + i ] );
        __m128i u    = _mm_loadu_si128( (void const *)( out + j1     ) );
        __m128i v    = _mm_loadu_si128( (void const *)( out + j1 + 4 ) );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_shoup_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv, spv );
        _mm_storeu_si128( (void *)( out + j1     ),
                          reduce_add ? fq_mul_shoup_sse( sum, one128, pone128 ) : sum );
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
        uint32_t s0  = falcon_psi_negative[ h + i     ];
        uint32_t s1  = falcon_psi_negative[ h + i + 1 ];
        uint32_t sp0 = s_prime_neg        [ h + i     ];
        uint32_t sp1 = s_prime_neg        [ h + i + 1 ];
        __m128i sv  = _mm_setr_epi32( (int)s0,  (int)s0,  (int)s1,  (int)s1 );
        __m128i spv = _mm_setr_epi32( (int)sp0, (int)sp0, (int)sp1, (int)sp1 );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_shoup_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv, spv );
        if( reduce_add ) sum = fq_mul_shoup_sse( sum, one128, pone128 );
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
        __m128i spv = _mm_loadu_si128( (void const *)( s_prime_neg         + h + i ) );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_shoup_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv, spv );
        if( reduce_add ) sum = fq_mul_shoup_sse( sum, one128, pone128 );
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

  __m512i n_inv  = _mm512_set1_epi32( 12265 );
  __m512i n_invp = _mm512_set1_epi32( (int)S_PRIME_NINV );
  for( uint32_t j=0; j<(uint32_t)N; j+=16 ) {
    __m512i x = _mm512_loadu_si512( (void const *)( out + j ) );
    _mm512_storeu_si512( (void *)( out + j ), fq_mul_shoup_v( x, n_inv, n_invp ) );
  }
}

int
falcon3_avx512_crypto_sign_open( uint8_t       * m,  size_t * mlen,
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

  /* Merged forward NTT: NTT(h) and NTT(s2) computed together. */
  ntt_fwd2_avx512( h_ntt, pubk->h, s2_ntt, sig->s2 );

  /* Hadamard: same as falcon2_avx512 (Barrett, since neither operand
     has a precomputed s'). */
  for( int i=0; i<N; i+=16 ) {
    __m512i a = _mm512_loadu_si512( (void const *)( s2_ntt + i ) );
    __m512i b = _mm512_loadu_si512( (void const *)( h_ntt  + i ) );
    __m512i Mv  = _mm512_set1_epi32( (int)43687U );
    __m512i Qv  = _mm512_set1_epi32( Q );
    __m512i mask_e = _mm512_set1_epi64( 0xFFFFFFFFLL );
    __m512i product = _mm512_mullo_epi32( a, b );
    __m512i wide_e = _mm512_mul_epu32( product, Mv );
    __m512i qest_e = _mm512_srli_epi64( wide_e, 29 );
    __m512i prod_o = _mm512_srli_epi64( product, 32 );
    __m512i wide_o = _mm512_mul_epu32( prod_o, Mv );
    __m512i qest_o = _mm512_srli_epi64( wide_o, 29 );
    __m512i qest_o_s = _mm512_slli_epi64( qest_o, 32 );
    __m512i qest = _mm512_or_si512( _mm512_and_si512( qest_e, mask_e ), qest_o_s );
    __m512i r = _mm512_sub_epi32( product, _mm512_mullo_epi32( qest, Qv ) );
    __m512i d    = _mm512_sub_epi32( r, Qv );
    __m512i sign = _mm512_srai_epi32( d, 31 );
    _mm512_storeu_si512( (void *)( prod + i ),
                         _mm512_add_epi32( d, _mm512_and_si512( Qv, sign ) ) );
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
falcon3_avx512_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                 uint8_t const * sm, size_t   smlen,
                                 uint8_t const * pk ) {
  return falcon_ref_crypto_sign_open( m, mlen, sm, smlen, pk );
}

#endif
