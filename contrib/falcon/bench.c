/* bench.c - microbenchmark harness for contrib/falcon.
 *
 * Three tables are produced:
 *   1. SHAKE256, comparing Pornin's (round-3 vendored) `inner_shake256_*`
 *      with XKCP's plain64 and AVX-512 single-stream variants of the
 *      same primitive.
 *   2. Raw Keccak-f[1600] permutation, comparing XKCP's plain64,
 *      single-stream AVX-512, and 8-way parallel AVX-512 (`times8`).
 *      Reported as ns/state, so directly comparable with the rows
 *      printed by Firedancer's `test_keccak256`.
 *   3. Falcon-512 verification end-to-end, with one row per verifier
 *      exposed in falcon.h:
 *        - falcon_ref            (Pornin shake.c, scalar)
 *        - falcon_ref_xkcp       (XKCP plain64 SHAKE, scalar)
 *        - falcon1_xkcp          (ref_xkcp + scalar Barrett+lazy NTT)
 *        - falcon2_xkcp          (ref_xkcp + scalar 64-bit-window comp_decode)
 *        - falcon_ref_turbopar   (TurboSHAKE12 + 8-way parallel squeeze)
 *        - falcon_avx512         (this work)
 *
 * Usage:
 *   ./bench                # plain text tables
 *   ./bench --latex        # LaTeX booktabs tables
 *   ./bench --iter N       # set the per-batch iteration count (default 10000)
 *
 * Times are wall-clock, measured with clock_gettime(CLOCK_MONOTONIC).
 * The harness reports the best of three batches to reduce jitter, and
 * runs a correctness check before timing. */

#include "falcon.h"
#include "test_vectors.h"
#include "xkcp_shake.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Forward declarations of Pornin's SHAKE256 (vendor/falcon-round3). */
typedef struct {
  union { uint64_t A[25]; uint8_t dbuf[200]; } st;
  uint64_t dptr;
} inner_shake256_context;
extern void falcon_inner_i_shake256_init   ( inner_shake256_context * sc );
extern void falcon_inner_i_shake256_inject ( inner_shake256_context * sc,
                                             const void * data, size_t len );
extern void falcon_inner_i_shake256_flip   ( inner_shake256_context * sc );
extern void falcon_inner_i_shake256_extract( inner_shake256_context * sc,
                                             void * out, size_t len );

/* SHAKE bench parameters: representative of a Falcon hash-to-point call.
 * 40 bytes nonce + 5 bytes message = 45 bytes input; squeeze ~1024 bytes
 * (slightly more than what hash-to-point consumes for N=512). */
#define SHAKE_IN_LEN   45
#define SHAKE_OUT_LEN  1024

/* Raw Keccak-f[1600] entry points (vendor/xkcp). */
typedef struct { uint64_t A[ 25 ]; } kp1600_state_t;
extern void KeccakP1600_plain64_Permute_24rounds( kp1600_state_t * st );
extern void KeccakP1600_AVX512_Permute_24rounds ( kp1600_state_t * st );

/* The 8-way parallel state is 25 ZMM lanes (= 25 * 64 bytes = 1600 B,
 * same total size as 8 separate single states). */
typedef struct { uint64_t A[ 8 * 25 ] __attribute__((aligned(64))); } kp1600_x8_state_t;
extern void KeccakP1600times8_AVX512_PermuteAll_24rounds( kp1600_x8_state_t * st );

static double
now_ns( void ) {
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

#define BENCH_BATCH( BODY, ITER, OUT ) do {                                  \
    double best = 1e30;                                                      \
    for( int _b=0; _b<3; _b++ ) {                                            \
      double t0 = now_ns();                                                  \
      for( unsigned long _i=0; _i<(ITER); _i++ ) { BODY; }                   \
      double t1 = now_ns();                                                  \
      double per = ( t1 - t0 ) / (double)(ITER);                             \
      if( per < best ) best = per;                                           \
    }                                                                        \
    (OUT) = best;                                                            \
  } while(0)

static int g_sink;
#define SINK( x ) do { g_sink ^= (int)(uintptr_t)(x); } while(0)

/* ---------- SHAKE256 benches ---------- */

static double
bench_shake_falcon_ref( unsigned long iter ) {
  uint8_t in [ SHAKE_IN_LEN  ];
  uint8_t out[ SHAKE_OUT_LEN ];
  for( int i=0; i<SHAKE_IN_LEN; i++ ) in[ i ] = (uint8_t)i;
  double r;
  BENCH_BATCH( ({
    inner_shake256_context sc;
    falcon_inner_i_shake256_init   ( &sc );
    falcon_inner_i_shake256_inject ( &sc, in, SHAKE_IN_LEN );
    falcon_inner_i_shake256_flip   ( &sc );
    falcon_inner_i_shake256_extract( &sc, out, SHAKE_OUT_LEN );
    SINK( out[ 0 ] );
  }), iter, r );
  return r;
}

static double
bench_shake_xkcp_plain64( unsigned long iter ) {
  uint8_t in [ SHAKE_IN_LEN  ];
  uint8_t out[ SHAKE_OUT_LEN ];
  for( int i=0; i<SHAKE_IN_LEN; i++ ) in[ i ] = (uint8_t)i;
  double r;
  BENCH_BATCH( ({
    xkcp_shake256_plain64( in, SHAKE_IN_LEN, out, SHAKE_OUT_LEN );
    SINK( out[ 0 ] );
  }), iter, r );
  return r;
}

static double
bench_shake_xkcp_avx512( unsigned long iter ) {
  uint8_t in [ SHAKE_IN_LEN  ];
  uint8_t out[ SHAKE_OUT_LEN ];
  for( int i=0; i<SHAKE_IN_LEN; i++ ) in[ i ] = (uint8_t)i;
  double r;
  BENCH_BATCH( ({
    xkcp_shake256_AVX512( in, SHAKE_IN_LEN, out, SHAKE_OUT_LEN );
    SINK( out[ 0 ] );
  }), iter, r );
  return r;
}

/* ---------- Raw Keccak-f[1600] permutation benches ---------- */

static double
bench_perm_xkcp_plain64( unsigned long iter ) {
  kp1600_state_t st __attribute__((aligned(64)));
  for( int i=0; i<25; i++ ) st.A[ i ] = (uint64_t)i;
  double r;
  BENCH_BATCH( ({ KeccakP1600_plain64_Permute_24rounds( &st ); SINK( st.A[0] ); }), iter, r );
  return r;
}

static double
bench_perm_xkcp_avx512( unsigned long iter ) {
  kp1600_state_t st __attribute__((aligned(64)));
  for( int i=0; i<25; i++ ) st.A[ i ] = (uint64_t)i;
  double r;
  BENCH_BATCH( ({ KeccakP1600_AVX512_Permute_24rounds( &st ); SINK( st.A[0] ); }), iter, r );
  return r;
}

static double
bench_perm_xkcp_times8_avx512( unsigned long iter ) {
  kp1600_x8_state_t st;
  memset( &st, 0, sizeof(st) );
  double r;
  BENCH_BATCH( ({
    KeccakP1600times8_AVX512_PermuteAll_24rounds( &st );
    SINK( st.A[0] );
  }), iter, r );
  return r;
}

/* ---------- Verify benches ---------- */

static double
bench_verify_ref( unsigned long iter ) {
  uint8_t m[ 2048 ];
  size_t  ml;
  double  r;
  BENCH_BATCH( ({
    SINK( falcon_ref_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  }), iter, r );
  return r;
}

static double
bench_verify_ref_xkcp( unsigned long iter ) {
  uint8_t m[ 2048 ];
  size_t  ml;
  double  r;
  BENCH_BATCH( ({
    SINK( falcon_ref_xkcp_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  }), iter, r );
  return r;
}

static double
bench_verify_falcon1_xkcp( unsigned long iter ) {
  uint8_t m[ 2048 ];
  size_t  ml;
  double  r;
  BENCH_BATCH( ({
    SINK( falcon1_xkcp_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  }), iter, r );
  return r;
}

static double
bench_verify_falcon2_xkcp( unsigned long iter ) {
  uint8_t m[ 2048 ];
  size_t  ml;
  double  r;
  BENCH_BATCH( ({
    SINK( falcon2_xkcp_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  }), iter, r );
  return r;
}

static double
bench_verify_falcon3_xkcp( unsigned long iter ) {
  uint8_t m[ 2048 ];
  size_t  ml;
  double  r;
  BENCH_BATCH( ({
    SINK( falcon3_xkcp_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  }), iter, r );
  return r;
}

static double
bench_verify_falcon4_xkcp( unsigned long iter ) {
  uint8_t m[ 2048 ];
  size_t  ml;
  double  r;
  BENCH_BATCH( ({
    SINK( falcon4_xkcp_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  }), iter, r );
  return r;
}

static double
bench_verify_falcon2_avx512( unsigned long iter ) {
  uint8_t m[ 2048 ];
  size_t  ml;
  double  r;
  BENCH_BATCH( ({
    SINK( falcon2_avx512_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  }), iter, r );
  return r;
}

static double
bench_verify_falcon3_avx512( unsigned long iter ) {
  uint8_t m[ 2048 ];
  size_t  ml;
  double  r;
  BENCH_BATCH( ({
    SINK( falcon3_avx512_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  }), iter, r );
  return r;
}

#define BENCH_FALCON4( SUFFIX )                                              \
static double                                                                \
bench_verify_falcon4_avx512_##SUFFIX( unsigned long iter ) {                 \
  uint8_t m[ 2048 ];                                                         \
  size_t  ml;                                                                \
  double  r;                                                                 \
  BENCH_BATCH( ({                                                            \
    SINK( falcon4_avx512_##SUFFIX##_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) ); \
  }), iter, r );                                                             \
  return r;                                                                  \
}
BENCH_FALCON4( m1 )
BENCH_FALCON4( m2 )
BENCH_FALCON4( m4 )
BENCH_FALCON4( m8 )
#undef BENCH_FALCON4

static double
bench_verify_falcon5_avx512( unsigned long iter ) {
  uint8_t m[ 2048 ];
  size_t  ml;
  double  r;
  BENCH_BATCH( ({
    SINK( falcon5_avx512_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  }), iter, r );
  return r;
}

static double
bench_verify_ref_turbopar( unsigned long iter ) {
  uint8_t m[ 2048 ];
  size_t  ml;
  double  r;
  /* The turbopar verifier returns -1 on the standard test vector (its
   * hash-to-point produces a different `c`).  Importantly, `verify_raw`
   * still runs to completion before reporting failure, so the timing
   * below corresponds to a full verify with the parallel-squeeze
   * hash-to-point on the critical path. */
  BENCH_BATCH( ({
    SINK( falcon_ref_turbopar_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  }), iter, r );
  return r;
}

static double
bench_verify_avx512( unsigned long iter ) {
  uint8_t m[ 2048 ];
  size_t  ml;
  double  r;
  BENCH_BATCH( ({
    SINK( falcon_avx512_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  }), iter, r );
  return r;
}

/* ---------- Correctness ---------- */

static int
correctness( void ) {
  uint8_t m1[ 2048 ], m2[ 2048 ], m3[ 2048 ];
  size_t  ml1 = 0, ml2 = 0, ml3 = 0;
  if( falcon_ref_crypto_sign_open(      m1, &ml1, tv_sm, tv_sm_len, tv_pubkey ) ) return 1;
  if( falcon_ref_xkcp_crypto_sign_open( m2, &ml2, tv_sm, tv_sm_len, tv_pubkey ) ) return 2;
  if( falcon_avx512_crypto_sign_open(   m3, &ml3, tv_sm, tv_sm_len, tv_pubkey ) ) return 3;
  if( ml1 != TV_MSG_LEN || ml2 != TV_MSG_LEN || ml3 != TV_MSG_LEN )               return 4;
  if( memcmp( m1, tv_msg, TV_MSG_LEN ) ||
      memcmp( m2, tv_msg, TV_MSG_LEN ) ||
      memcmp( m3, tv_msg, TV_MSG_LEN ) )                                          return 5;

  /* falcon1..4_xkcp / falcon2_avx512 / falcon3_avx512 must verify the
   * same vector. */
  uint8_t m1b[ 2048 ], m2b[ 2048 ], m3b[ 2048 ], m4b[ 2048 ], m5b[ 2048 ], m6b[ 2048 ];
  size_t  ml1b=0, ml2b=0, ml3b=0, ml4b=0, ml5b=0, ml6b=0;
  if( falcon1_xkcp_crypto_sign_open  ( m1b, &ml1b, tv_sm, tv_sm_len, tv_pubkey ) )                 return  9;
  if( falcon2_xkcp_crypto_sign_open  ( m2b, &ml2b, tv_sm, tv_sm_len, tv_pubkey ) )                 return 10;
  if( falcon3_xkcp_crypto_sign_open  ( m3b, &ml3b, tv_sm, tv_sm_len, tv_pubkey ) )                 return 13;
  if( falcon4_xkcp_crypto_sign_open  ( m4b, &ml4b, tv_sm, tv_sm_len, tv_pubkey ) )                 return 14;
  if( falcon2_avx512_crypto_sign_open( m5b, &ml5b, tv_sm, tv_sm_len, tv_pubkey ) )                 return 15;
  if( falcon3_avx512_crypto_sign_open( m6b, &ml6b, tv_sm, tv_sm_len, tv_pubkey ) )                 return 16;
  if( ml1b != TV_MSG_LEN || ml2b != TV_MSG_LEN || ml3b != TV_MSG_LEN ||
      ml4b != TV_MSG_LEN || ml5b != TV_MSG_LEN || ml6b != TV_MSG_LEN )                             return 11;
  if( memcmp( m1b, tv_msg, TV_MSG_LEN ) || memcmp( m2b, tv_msg, TV_MSG_LEN ) ||
      memcmp( m3b, tv_msg, TV_MSG_LEN ) || memcmp( m4b, tv_msg, TV_MSG_LEN ) ||
      memcmp( m5b, tv_msg, TV_MSG_LEN ) || memcmp( m6b, tv_msg, TV_MSG_LEN ) )                     return 12;

  /* falcon4_avx512_m1/m2/m4/m8 must verify the same vector. */
  uint8_t m4a1[2048], m4a2[2048], m4a4[2048], m4a8[2048];
  size_t  ml4a1=0, ml4a2=0, ml4a4=0, ml4a8=0;
  if( falcon4_avx512_m1_crypto_sign_open( m4a1, &ml4a1, tv_sm, tv_sm_len, tv_pubkey ) )            return 17;
  if( falcon4_avx512_m2_crypto_sign_open( m4a2, &ml4a2, tv_sm, tv_sm_len, tv_pubkey ) )            return 18;
  if( falcon4_avx512_m4_crypto_sign_open( m4a4, &ml4a4, tv_sm, tv_sm_len, tv_pubkey ) )            return 19;
  if( falcon4_avx512_m8_crypto_sign_open( m4a8, &ml4a8, tv_sm, tv_sm_len, tv_pubkey ) )            return 20;
  if( ml4a1 != TV_MSG_LEN || ml4a2 != TV_MSG_LEN ||
      ml4a4 != TV_MSG_LEN || ml4a8 != TV_MSG_LEN )                                                 return 21;
  if( memcmp( m4a1, tv_msg, TV_MSG_LEN ) || memcmp( m4a2, tv_msg, TV_MSG_LEN ) ||
      memcmp( m4a4, tv_msg, TV_MSG_LEN ) || memcmp( m4a8, tv_msg, TV_MSG_LEN ) )                   return 22;

  /* falcon5_avx512 (Barrett + merged) must verify the same vector. */
  uint8_t f5buf[ 2048 ];
  size_t  ml5br = 0;
  if( falcon5_avx512_crypto_sign_open( f5buf, &ml5br, tv_sm, tv_sm_len, tv_pubkey ) )              return 23;
  if( ml5br != TV_MSG_LEN )                                                                        return 24;
  if( memcmp( f5buf, tv_msg, TV_MSG_LEN ) )                                                        return 25;

  /* falcon_ref_turbopar: just check it runs deterministically. */
  uint8_t mta[ 2048 ], mtb[ 2048 ];
  size_t  mlta = 0, mltb = 0;
  int     rta = falcon_ref_turbopar_crypto_sign_open( mta, &mlta, tv_sm, tv_sm_len, tv_pubkey );
  int     rtb = falcon_ref_turbopar_crypto_sign_open( mtb, &mltb, tv_sm, tv_sm_len, tv_pubkey );
  if( rta != rtb || mlta != mltb ) return 6;

  /* SHAKE: all three implementations must produce the same output. */
  uint8_t in[ SHAKE_IN_LEN ], a[ SHAKE_OUT_LEN ], b[ SHAKE_OUT_LEN ], c[ SHAKE_OUT_LEN ];
  for( int i=0; i<SHAKE_IN_LEN; i++ ) in[ i ] = (uint8_t)i;

  inner_shake256_context sc;
  falcon_inner_i_shake256_init   ( &sc );
  falcon_inner_i_shake256_inject ( &sc, in, SHAKE_IN_LEN );
  falcon_inner_i_shake256_flip   ( &sc );
  falcon_inner_i_shake256_extract( &sc, a, SHAKE_OUT_LEN );
  xkcp_shake256_plain64( in, SHAKE_IN_LEN, b, SHAKE_OUT_LEN );
  xkcp_shake256_AVX512 ( in, SHAKE_IN_LEN, c, SHAKE_OUT_LEN );
  if( memcmp( a, b, SHAKE_OUT_LEN ) ) return 7;
  if( memcmp( a, c, SHAKE_OUT_LEN ) ) return 8;
  return 0;
}

/* ---------- Output formatting ---------- */

static void
emit_text_shake( double falcon_ns, double xkcp_p_ns, double xkcp_a_ns ) {
  printf( "SHAKE256, %d-byte input, %d-byte output, ns/call:\n",
          SHAKE_IN_LEN, SHAKE_OUT_LEN );
  printf( "  %-30s %12.1f\n", "Falcon ref (Pornin shake.c)", falcon_ns );
  printf( "  %-30s %12.1f  (%.2fx)\n", "XKCP plain64 (scalar)",
          xkcp_p_ns, falcon_ns / xkcp_p_ns );
  printf( "  %-30s %12.1f  (%.2fx)\n", "XKCP AVX-512 (single stream)",
          xkcp_a_ns, falcon_ns / xkcp_a_ns );
}

static void
emit_text_verify( double ref_ns, double ref_xkcp_ns,
                  double f1_ns, double f2_ns, double f3_ns, double f4_ns,
                  double ref_turbopar_ns,
                  double avx_ns, double avx2_ns, double avx3_ns,
                  double avx4_m1_ns, double avx4_m2_ns,
                  double avx4_m4_ns, double avx4_m8_ns,
                  double avx5_ns ) {
  printf( "Verify (NIST API, %zu-byte signed message), ns/call:\n", tv_sm_len );
  printf( "  %-36s %12.1f\n",                "falcon_ref (vendored Pornin)", ref_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon_ref_xkcp (XKCP SHAKE)",
          ref_xkcp_ns, ref_ns / ref_xkcp_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon1_xkcp (lazy Barrett NTT)",
          f1_ns, ref_ns / f1_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon2_xkcp (fast comp_decode)",
          f2_ns, ref_ns / f2_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon3_xkcp (vectorizer-friendly C)",
          f3_ns, ref_ns / f3_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon4_xkcp (Shoup NTT, scalar)",
          f4_ns, ref_ns / f4_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon_ref_turbopar (TS12,K=8)",
          ref_turbopar_ns, ref_ns / ref_turbopar_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon_avx512 (Barrett NTT)",
          avx_ns, ref_ns / avx_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon2_avx512 (Shoup NTT)",
          avx2_ns, ref_ns / avx2_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon3_avx512 (Shoup, merged fwd NTT)",
          avx3_ns, ref_ns / avx3_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon4_avx512_m1 (Shoup, merge t<=1)",
          avx4_m1_ns, ref_ns / avx4_m1_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon4_avx512_m2 (Shoup, merge t<=2)",
          avx4_m2_ns, ref_ns / avx4_m2_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon4_avx512_m4 (Shoup, merge t<=4)",
          avx4_m4_ns, ref_ns / avx4_m4_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon4_avx512_m8 (Shoup, merge t<=8)",
          avx4_m8_ns, ref_ns / avx4_m8_ns );
  printf( "  %-36s %12.1f  (%.2fx)\n",       "falcon5_avx512 (Barrett, merged fwd NTT)",
          avx5_ns, ref_ns / avx5_ns );
}

static void
emit_latex_shake( double falcon_ns, double xkcp_p_ns, double xkcp_a_ns ) {
  printf( "%% Generated by contrib/falcon/bench --latex\n" );
  printf( "\\begin{table}[t]\n\\centering\n" );
  printf( "\\caption{SHAKE256 throughput: %d-byte input, %d-byte output. "
          "``Falcon ref'' is the SHAKE shipped with the round 3 reference "
          "(\\texttt{inner\\_shake256\\_*}).  ``XKCP'' is the eXtended "
          "Keccak Code Package, vendored unmodified at "
          "\\texttt{contrib/falcon/vendor/xkcp}.}\n",
          SHAKE_IN_LEN, SHAKE_OUT_LEN );
  printf( "\\label{tab:shake}\n\\begin{tabular}{lrr}\n\\toprule\n" );
  printf( "\\textbf{Implementation} & \\textbf{ns/call} & \\textbf{Speedup} \\\\\n" );
  printf( "\\midrule\n" );
  printf( "Falcon ref (scalar)        & %10.1f & %14s \\\\\n", falcon_ns, "1.00$\\times$" );
  printf( "XKCP plain64 (scalar)      & %10.1f & %12.2f$\\times$ \\\\\n", xkcp_p_ns, falcon_ns / xkcp_p_ns );
  printf( "XKCP AVX-512 (1 stream)    & %10.1f & %12.2f$\\times$ \\\\\n", xkcp_a_ns, falcon_ns / xkcp_a_ns );
  printf( "\\bottomrule\n\\end{tabular}\n\\end{table}\n" );
}

static void
emit_latex_verify( double ref_ns, double ref_xkcp_ns,
                   double f1_ns, double f2_ns, double f3_ns, double f4_ns,
                   double ref_turbopar_ns,
                   double avx_ns, double avx2_ns, double avx3_ns ) {
  printf( "\\begin{table}[t]\n\\centering\n" );
  printf( "\\caption{Falcon-512 verification on the test machine, in nanoseconds. "
          "Rows 1--6 are scalar (no SIMD intrinsics); row 7 uses the "
          "non-standard TurboSHAKE256 + 8-way parallel-squeeze variant from "
          "Section~\\ref{sec:parsq}; rows 8--10 use the AVX-512 implementations "
          "in \\texttt{contrib/falcon/falcon\\_avx512.c}, "
          "\\texttt{falcon2\\_avx512.c}, and \\texttt{falcon3\\_avx512.c}.}\n" );
  printf( "\\label{tab:verify}\n\\begin{tabular}{lrr}\n\\toprule\n" );
  printf( "\\textbf{Implementation} & \\textbf{ns/call} & \\textbf{Speedup} \\\\\n" );
  printf( "\\midrule\n" );
  printf( "\\texttt{falcon\\_ref}                                 & %10.1f & %14s \\\\\n",
          ref_ns, "1.00$\\times$" );
  printf( "\\texttt{falcon\\_ref\\_xkcp}                          & %10.1f & %12.2f$\\times$ \\\\\n",
          ref_xkcp_ns, ref_ns / ref_xkcp_ns );
  printf( "\\texttt{falcon1\\_xkcp} (Barrett + lazy NTT, scalar)  & %10.1f & %12.2f$\\times$ \\\\\n",
          f1_ns, ref_ns / f1_ns );
  printf( "\\texttt{falcon2\\_xkcp} (window \\texttt{comp\\_decode}) & %10.1f & %12.2f$\\times$ \\\\\n",
          f2_ns, ref_ns / f2_ns );
  printf( "\\texttt{falcon3\\_xkcp} (vectorizer-friendly C)        & %10.1f & %12.2f$\\times$ \\\\\n",
          f3_ns, ref_ns / f3_ns );
  printf( "\\texttt{falcon4\\_xkcp} (Shoup NTT, scalar)            & %10.1f & %12.2f$\\times$ \\\\\n",
          f4_ns, ref_ns / f4_ns );
  printf( "\\texttt{falcon\\_ref\\_turbopar}                      & %10.1f & %12.2f$\\times$ \\\\\n",
          ref_turbopar_ns, ref_ns / ref_turbopar_ns );
  printf( "\\texttt{falcon\\_avx512} (Barrett NTT)                 & %10.1f & %12.2f$\\times$ \\\\\n",
          avx_ns, ref_ns / avx_ns );
  printf( "\\texttt{falcon2\\_avx512} (Shoup NTT)                  & %10.1f & %12.2f$\\times$ \\\\\n",
          avx2_ns, ref_ns / avx2_ns );
  printf( "\\texttt{falcon3\\_avx512} (Shoup, merged fwd NTT)       & %10.1f & %12.2f$\\times$ \\\\\n",
          avx3_ns, ref_ns / avx3_ns );
  printf( "\\bottomrule\n\\end{tabular}\n\\end{table}\n" );
}

int
main( int argc, char ** argv ) {
  unsigned long iter = 10000;
  int latex = 0;
  for( int i=1; i<argc; i++ ) {
    if(      !strcmp( argv[ i ], "--latex" ) )                  latex = 1;
    else if( !strcmp( argv[ i ], "--iter" ) && i+1<argc )       iter  = strtoul( argv[ ++i ], NULL, 10 );
    else if( !strcmp( argv[ i ], "-h" ) || !strcmp( argv[ i ], "--help" ) ) {
      fprintf( stderr,
               "usage: %s [--latex] [--iter N]\n"
               "  --latex    emit LaTeX booktabs tables\n"
               "  --iter N   number of iterations per batch (default 10000)\n",
               argv[ 0 ] );
      return 0;
    }
    else { fprintf( stderr, "unknown arg %s\n", argv[ i ] ); return 1; }
  }

  tv_make_signed_message();
  if( !tv_sm_len ) { fprintf( stderr, "tv_make_signed_message failed\n" ); return 1; }
  int rc = correctness();
  if( rc ) { fprintf( stderr, "correctness failed (rc=%d)\n", rc ); return 1; }
  if( !latex ) fprintf( stderr, "correctness: ok, iter=%lu\n", iter );

  double shake_falcon  = bench_shake_falcon_ref     ( iter );
  double shake_p64     = bench_shake_xkcp_plain64   ( iter );
  double shake_avx512  = bench_shake_xkcp_avx512    ( iter );

  double verify_ref    = bench_verify_ref           ( iter );
  double verify_xkcp   = bench_verify_ref_xkcp      ( iter );
  double verify_f1     = bench_verify_falcon1_xkcp  ( iter );
  double verify_f2     = bench_verify_falcon2_xkcp  ( iter );
  double verify_f3     = bench_verify_falcon3_xkcp  ( iter );
  double verify_f4     = bench_verify_falcon4_xkcp  ( iter );
  double verify_tpar   = bench_verify_ref_turbopar  ( iter );
  double verify_avx    = bench_verify_avx512        ( iter );
  double verify_avx2   = bench_verify_falcon2_avx512( iter );
  double verify_avx3   = bench_verify_falcon3_avx512( iter );
  double verify_avx4_m1 = bench_verify_falcon4_avx512_m1( iter );
  double verify_avx4_m2 = bench_verify_falcon4_avx512_m2( iter );
  double verify_avx4_m4 = bench_verify_falcon4_avx512_m4( iter );
  double verify_avx4_m8 = bench_verify_falcon4_avx512_m8( iter );
  double verify_avx5    = bench_verify_falcon5_avx512   ( iter );

  /* Raw permutation table.  ITER for raw perms can be larger because each
   * call is much cheaper. */
  unsigned long perm_iter = iter * 8UL;
  double perm_p64    = bench_perm_xkcp_plain64       ( perm_iter );
  double perm_avx512 = bench_perm_xkcp_avx512        ( perm_iter );
  double perm_x8     = bench_perm_xkcp_times8_avx512 ( perm_iter );

  if( latex ) {
    emit_latex_shake ( shake_falcon, shake_p64, shake_avx512 );
    printf( "\n" );
    emit_latex_verify( verify_ref, verify_xkcp,
                       verify_f1, verify_f2, verify_f3, verify_f4,
                       verify_tpar, verify_avx, verify_avx2, verify_avx3 );
  } else {
    emit_text_shake  ( shake_falcon, shake_p64, shake_avx512 );
    printf( "\n" );
    emit_text_verify ( verify_ref, verify_xkcp,
                       verify_f1, verify_f2, verify_f3, verify_f4,
                       verify_tpar, verify_avx, verify_avx2, verify_avx3,
                       verify_avx4_m1, verify_avx4_m2,
                       verify_avx4_m4, verify_avx4_m8,
                       verify_avx5 );
    printf( "\n" );
    printf( "Raw Keccak-f[1600] permutation, ns/state:\n" );
    printf( "  %-30s %12.1f\n", "XKCP plain64 (1 state)",   perm_p64 );
    printf( "  %-30s %12.1f\n", "XKCP AVX-512 (1 state)",   perm_avx512 );
    printf( "  %-30s %12.1f  (%.1f ns/call x 8 lanes)\n",
            "XKCP times8 AVX-512", perm_x8 / 8.0, perm_x8 );
  }
  return 0;
}
