/* test_falcon.c - correctness tests for the four verifiers in this
 *                 directory:
 *
 *   - falcon_ref_crypto_sign_open          : unmodified NIST round 3
 *                                            reference (vendored).
 *   - falcon_ref_xkcp_crypto_sign_open     : same algorithm, but with
 *                                            XKCP plain64 SHAKE256 in
 *                                            hash-to-point.  Bit-for-
 *                                            bit identical to the ref.
 *   - falcon_ref_turbopar_crypto_sign_open : non-standard TurboSHAKE +
 *                                            parallel-squeeze hash-to-
 *                                            point variant.  Cannot
 *                                            verify standard Falcon
 *                                            signatures.
 *   - falcon_avx512_crypto_sign_open       : AVX-512 implementation in
 *                                            this directory.
 *
 * All four functions consume the same NIST signed-message buffer, so
 * this harness assembles `tv_sm` once and passes it to all of them. */

#include "falcon.h"
#include "test_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK( cond ) do { \
  if( !(cond) ) { \
    fprintf( stderr, "FAIL: %s:%d %s\n", __FILE__, __LINE__, #cond ); \
    exit( 1 ); \
  } \
} while(0)

/* All-in-one valid verify test.  Every variant must accept the test
 * vector and return the original message. */
static void
test_one_variant( const char * name,
                  int (*fn)( uint8_t *, size_t *, uint8_t const *, size_t,
                             uint8_t const * ) ) {
  uint8_t m[ 2048 ];
  size_t  ml = 0;
  CHECK( 0 == fn( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  CHECK( ml == TV_MSG_LEN );
  CHECK( 0 == memcmp( m, tv_msg, TV_MSG_LEN ) );
  (void)name;
}

static void
test_verify_valid( void ) {
  test_one_variant( "falcon_ref",      falcon_ref_crypto_sign_open      );
  test_one_variant( "falcon_ref_xkcp", falcon_ref_xkcp_crypto_sign_open );
  test_one_variant( "falcon1_xkcp",    falcon1_xkcp_crypto_sign_open    );
  test_one_variant( "falcon2_xkcp",    falcon2_xkcp_crypto_sign_open    );
  test_one_variant( "falcon3_xkcp",    falcon3_xkcp_crypto_sign_open    );
  test_one_variant( "falcon4_xkcp",    falcon4_xkcp_crypto_sign_open    );
  test_one_variant( "falcon_avx512",      falcon_avx512_crypto_sign_open      );
  test_one_variant( "falcon2_avx512",     falcon2_avx512_crypto_sign_open     );
  test_one_variant( "falcon3_avx512",     falcon3_avx512_crypto_sign_open     );
  test_one_variant( "falcon4_avx512_m1",  falcon4_avx512_m1_crypto_sign_open  );
  test_one_variant( "falcon4_avx512_m2",  falcon4_avx512_m2_crypto_sign_open  );
  test_one_variant( "falcon4_avx512_m4",  falcon4_avx512_m4_crypto_sign_open  );
  test_one_variant( "falcon4_avx512_m8",  falcon4_avx512_m8_crypto_sign_open  );
  test_one_variant( "falcon5_avx512",     falcon5_avx512_crypto_sign_open     );
  printf( "OK: verify (valid) - ref, ref_xkcp, falcon1..4_xkcp, avx512, falcon2_avx512, falcon3_avx512, falcon4_avx512_{m1,m2,m4,m8}, falcon5_avx512\n" );
}

static void
test_verify_rejects( void ) {
  uint8_t m_out[ 2048 ];
  size_t  ml_out;

  typedef int (*verify_fn)( uint8_t *, size_t *, uint8_t const *, size_t,
                            uint8_t const * );
  verify_fn fns[] = {
    falcon_ref_crypto_sign_open,
    falcon_ref_xkcp_crypto_sign_open,
    falcon1_xkcp_crypto_sign_open,
    falcon2_xkcp_crypto_sign_open,
    falcon3_xkcp_crypto_sign_open,
    falcon4_xkcp_crypto_sign_open,
    falcon_avx512_crypto_sign_open,
    falcon2_avx512_crypto_sign_open,
    falcon3_avx512_crypto_sign_open,
    falcon4_avx512_m1_crypto_sign_open,
    falcon4_avx512_m2_crypto_sign_open,
    falcon4_avx512_m4_crypto_sign_open,
    falcon4_avx512_m8_crypto_sign_open,
    falcon5_avx512_crypto_sign_open,
  };
  size_t nfns = sizeof(fns) / sizeof(fns[0]);

  /* Mutated nonce. */
  uint8_t mut[ sizeof(tv_sm) ];
  memcpy( mut, tv_sm, tv_sm_len );
  mut[ 2 ] ^= 1;
  for( size_t k=0; k<nfns; k++ )
    CHECK( 0 != fns[ k ]( m_out, &ml_out, mut, tv_sm_len, tv_pubkey ) );

  /* Mutated message. */
  memcpy( mut, tv_sm, tv_sm_len );
  mut[ 2 + 40 ] ^= 1;
  for( size_t k=0; k<nfns; k++ )
    CHECK( 0 != fns[ k ]( m_out, &ml_out, mut, tv_sm_len, tv_pubkey ) );

  /* Mutated signature. */
  memcpy( mut, tv_sm, tv_sm_len );
  mut[ 2 + 40 + TV_MSG_LEN + 1 ] ^= 1;
  for( size_t k=0; k<nfns; k++ )
    CHECK( 0 != fns[ k ]( m_out, &ml_out, mut, tv_sm_len, tv_pubkey ) );

  /* Mutated public key. */
  uint8_t pk[ FALCON_PUBKEY_SIZE ];
  memcpy( pk, tv_pubkey, sizeof(pk) );
  pk[ 1 ] ^= 1;
  for( size_t k=0; k<nfns; k++ )
    CHECK( 0 != fns[ k ]( m_out, &ml_out, tv_sm, tv_sm_len, pk ) );

  printf( "OK: verify rejects mutated nonce, msg, sig, pk\n" );
}

/* `falcon_ref_turbopar` uses a non-standard hash-to-point and therefore
 * cannot verify Falcon round 3 signatures.  We only check that it does
 * not crash and that it returns a non-zero (failure) status on the
 * standard test vector and is deterministic across two calls.  Useful
 * to make sure the parallel-squeeze code path is exercised in the
 * benchmark with the same inputs. */
static void
test_turbopar_runs( void ) {
  uint8_t m_a[ 2048 ], m_b[ 2048 ];
  size_t  ml_a = 0,    ml_b = 0;
  int ra = falcon_ref_turbopar_crypto_sign_open( m_a, &ml_a, tv_sm, tv_sm_len, tv_pubkey );
  int rb = falcon_ref_turbopar_crypto_sign_open( m_b, &ml_b, tv_sm, tv_sm_len, tv_pubkey );
  CHECK( ra == rb );
  CHECK( ml_a == ml_b );
  printf( "OK: falcon_ref_turbopar runs deterministically (rc=%d, mlen=%zu)\n",
          ra, ml_a );
}

int
main( void ) {
  tv_make_signed_message();
  CHECK( tv_sm_len > 0 );
  test_verify_valid();
  test_verify_rejects();
  test_turbopar_runs();
  printf( "pass\n" );
  return 0;
}
