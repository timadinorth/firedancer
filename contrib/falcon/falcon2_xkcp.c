/* falcon2_xkcp.c - Falcon-512 verification, scalar.
 *
 * Starting point: `falcon_ref_xkcp.c` (Pornin parsers + XKCP plain64
 * SHAKE256 + Pornin's NTT pipeline).  This file applies Improvement 2
 * from the paper to that baseline:
 *
 *   - Signature decoding (`comp_decode`) is rewritten with a 64-bit
 *     window into the bit stream, an unaligned 64-bit load + byteswap,
 *     and `__builtin_clzll` to count the unary high bits in a single
 *     instruction (Section "Signature: Variable-Length Decoding").
 *
 * Public-key parsing, hash-to-point, and the NTT pipeline (`verify_raw`)
 * are reused unmodified from the vendored Pornin reference; this
 * isolates the wall-clock contribution of the new signature decoder.
 *
 * No SIMD intrinsics are used; the scalar version of the algorithm
 * relies only on `__builtin_clzll` and `__builtin_bswap64`, both of
 * which compile to a single instruction on x86-64.
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
#define K_REJ        ( ( 1 << 16 ) / Q ) /* 5 */
#define SHAKE_RATE   136                   /* (1600 - 2*256) / 8 */

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

/* --- Pornin internals (vendor/falcon-round3) --- */
extern size_t falcon_inner_modq_decode  ( uint16_t * x, unsigned logn,
                                          void const * in, size_t max_in_len );
extern void   falcon_inner_to_ntt_monty ( uint16_t * h, unsigned logn );
extern int    falcon_inner_verify_raw   ( uint16_t const * c0,
                                          int16_t  const * s2,
                                          uint16_t const * h,
                                          unsigned logn, uint8_t * tmp );

/* --- XKCP plain64 Keccak-p[1600] --- */
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

/* ---------- compressed s2 parsing (scalar, 64-bit window).
 *
 * The compressed encoding writes each coefficient as
 *     [sign : 1] [low : 7] [0^k] [1]
 * where k unary zeros encode the high bits of the magnitude.  The
 * Pornin reference scans bits one at a time.  We instead keep a 64-bit
 * window into the bit stream:
 *
 *   1. Load 8 bytes at the current bit position with an unaligned
 *      64-bit load and a byteswap, then left-shift by the sub-byte
 *      offset to align to bit 0.
 *   2. Extract sign and 7-bit low from the top 8 bits.
 *   3. Count unary zeros in the remaining 56 bits with __builtin_clzll
 *      (compiles to a single lzcnt/bsr).
 *   4. Advance the bit pointer by 8 + k + 1 and refill when fewer than
 *      16 bits remain.
 *
 * Output type is int16_t because that is what Pornin's `verify_raw`
 * expects; the magnitude fits in 14 bits so int16_t is sufficient. */

static inline uint64_t
load_u64( void const * p ) {
  uint64_t v;
  memcpy( &v, p, 8 );
  return v;
}

static int
parse_comp_s2_fast( int16_t * out_s2, uint8_t const * in, size_t in_len ) {
  size_t length = in_len * 8;

  /* Pad with 8 zero bytes so a 64-bit load is always well-defined,
   * even at the end of `in`. */
  uint8_t padded[ 1024 + 8 ] __attribute__((aligned(64)));
  if( UNLIKELY( in_len + 8 > sizeof(padded) ) ) return -1;
  memcpy( padded,         in, in_len );
  memset( padded + in_len, 0, 8 );

  size_t   abs_bit = 0;
  uint64_t word    = __builtin_bswap64( load_u64( padded ) );
  int      avail   = 64;

  for( int i=0; i<N; i++ ) {
    if( UNLIKELY( avail < 16 ) ) {
      /* A coefficient takes between 9 (sign + 7 + stop) and a few more
       * unary bits to encode.  We need at least 9 to extract sign and
       * low, plus the stop bit.  The unary fallback below has its own
       * `abs_bit >= length` check. */
      if( UNLIKELY( abs_bit + 9 > length ) ) return -1;
      size_t bp = abs_bit >> 3;
      int    sb = (int)( abs_bit & 7 );
      word  = __builtin_bswap64( load_u64( padded + bp ) ) << sb;
      avail = 64 - sb;
    }

    int      sign = (int)( word >> 63 );
    int      low  = (int)( ( word >> 56 ) & 0x7F );
    uint64_t tail = word << 8;

    int high;
    if( LIKELY( tail ) ) {
      high = (int)__builtin_clzll( tail );
      int advance = 9 + high;
      word    <<= advance;
      avail    -= advance;
      abs_bit  += (size_t)advance;
    } else {
      /* The 56-bit tail of the current window is all zeros: the unary
       * stop bit lies in the next window.  Refill and continue
       * counting. */
      high = avail - 8;
      abs_bit += 8;

      for( ;; ) {
        if( UNLIKELY( abs_bit >= length ) ) return -1;
        size_t bp = abs_bit >> 3;
        int    sb = (int)( abs_bit & 7 );
        word  = __builtin_bswap64( load_u64( padded + bp ) ) << sb;
        avail = 64 - sb;
        if( LIKELY( word ) ) {
          int extra   = (int)__builtin_clzll( word );
          high       += extra;
          int advance = extra + 1;
          word    <<= advance;
          avail    -= advance;
          abs_bit  += (size_t)advance;
          break;
        }
        if( UNLIKELY( (uint32_t)high >= (uint32_t)( Q >> 7 ) ) ) return -1;
        high    += avail;
        abs_bit += (size_t)avail;
        avail    = 0;
      }
    }

    if( UNLIKELY( abs_bit > length ) ) return -1;

    int mag = ( high << 7 ) | low;
    if( UNLIKELY( mag >= Q ) ) return -1;
    out_s2[ i ] = (int16_t)( sign ? -mag : mag );
  }

  /* Trailing bits must be zero (true for both round 3 unpadded and
   * FN-DSA padded encodings, since the latter pads with zeros). */
  if( abs_bit < length ) {
    size_t bp = abs_bit >> 3;
    int    sb = (int)( abs_bit & 7 );
    if( sb ) {
      uint8_t trail_mask = (uint8_t)( 0xFF >> sb );
      if( UNLIKELY( in[ bp ] & trail_mask ) ) return -1;
      bp++;
    }
    for( size_t j=bp; j<in_len; j++ ) {
      if( UNLIKELY( in[ j ] ) ) return -1;
    }
  }
  return 0;
}

/* ---------- hash-to-point with XKCP plain64 SHAKE256 (same as
 * `falcon_ref_xkcp.c`). ---------- */

static void
hash_to_point_xkcp( uint16_t * out, uint8_t const * in, size_t in_len ) {
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
        *out++ = (uint16_t)w;
        remaining--;
      }
    }
    if( !remaining ) break;
    KeccakP1600_plain64_Permute_24rounds( &st );
  }
}

int
falcon2_xkcp_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                               uint8_t const * sm, size_t   smlen,
                               uint8_t const * pk ) {
  uint8_t  tmp[ 2 * 512 ];
  uint16_t h[ 512 ], c0[ 512 ];
  int16_t  sig[ 512 ];

  /* Public-key parsing: Pornin's `modq_decode` + `to_ntt_monty`. */
  if( pk[ 0 ] != 0x00 + LOGN ) return -1;
  if( falcon_inner_modq_decode( h, LOGN, pk + 1,
                                FALCON_PUBKEY_SIZE - 1 )
      != FALCON_PUBKEY_SIZE - 1 ) return -1;
  falcon_inner_to_ntt_monty( h, LOGN );

  /* Wire format. */
  if( smlen < 2 + NONCELEN ) return -1;
  size_t sig_len = ( (size_t)sm[ 0 ] << 8 ) | (size_t)sm[ 1 ];
  if( sig_len > smlen - 2 - NONCELEN ) return -1;
  size_t msg_len = smlen - 2 - NONCELEN - sig_len;

  uint8_t const * esig = sm + 2 + NONCELEN + msg_len;
  if( sig_len < 1 || esig[ 0 ] != 0x20 + LOGN ) return -1;

  /* Signature parsing: our 64-bit-window scalar fast path. */
  if( parse_comp_s2_fast( sig, esig + 1, sig_len - 1 ) ) return -1;

  /* Hash-to-point with XKCP plain64 SHAKE256. */
  hash_to_point_xkcp( c0, sm + 2, NONCELEN + msg_len );

  /* Norm + NTT pipeline: Pornin's `verify_raw`. */
  if( !falcon_inner_verify_raw( c0, sig, h, LOGN, tmp ) ) return -1;

  if( m && msg_len ) memmove( m, sm + 2 + NONCELEN, msg_len );
  if( mlen ) *mlen = msg_len;
  return 0;
}
