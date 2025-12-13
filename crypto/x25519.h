#ifndef _X25519_H_
#define _X25519_H_

#define _KOCKET_SPECIAL_TYPE_SUPPORT_
#define _KOCKET_UTILS_IMPLEMENTATION_
#define _KOCKET_PRINTING_UTILS_
#define _KOCKET_NO_PERROR_SUPPORT_
#include "../kocket_utils.h"
#include "./chacha20.h"
#include "./ecm_ops.h"

/* Reference [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) */

typedef u8 x25519Scalar[32];

static void decode_scalar25519(x25519Scalar k) {
    k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;
    return;
}

// TODO: Could be that the encode/decode also switch from little endian to big
// endian, check this if encountering errors
#define encode_u_coordinate decode_u_coordinate
static x25519Scalar* decode_u_coordinate(x25519Scalar u) {
	ECMScalar decoded_u = ecm_mod(u, p);
	x25519Scalar d_u = {0};
	mem_cpy(d_u, decoded_u.data, sizeof(x25519Scalar));
	return d_u;
}

static x25519Scalar* and_scalar(x25519Scalar a, x25519Scalar b) {
	x25519Scalar scalar = {0};
	for (unsigned int i = 0; i < 32; ++i) scalar[i] = a[i] & b[i];
	return scalar;
}

static x25519Scalar* xor_scalar(x25519Scalar a, x25519Scalar b) {
	x25519Scalar scalar = {0};
	for (unsigned int i = 0; i < 32; ++i) scalar[i] = a[i] ^ b[i];
	return scalar;
}

// TODO: Implement me
static x25519Scalar* neg_scalar(x25519Scalar a) {
	x25519Scalar scalar = {0};
	for (unsigned int i = 0; i < 32; ++i) scalar[i] = a[i];
	TODO("Implement me");
	abort();
	return scalar;
}

static void x25519_cswap(x25519Scalar swap, x25519Scalar x2, x25519Scalar x3) {
    x25519Scalar mask = neg_scalar(swap);

    x25519Scalar t = and_scalar(mask, xor_scalar(x2, x3);
    
	x25519Scalar tx2 = xor_scalar(x2, t);
    x25519Scalar tx3 = xor_scalar(x3, x3, t);
    
	mem_cpy(x2, tx2, sizeof(x25519Scalar));
	mem_cpy(x3, tx3, sizeof(x25519Scalar));

	return;
}

static x25519Scalar clamp_scalar(const u8* k_data) {
	x25519Scalar k = {0};
	mem_cpy(k, k_data, sizeof(x25519Scalar));
    k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;
	return k;
}

static x25519Scalar x25519(x25519Scalar scalar_bytes, x25519Scalar bytes) {
    x25519Scalar result = {0};
	return result;

	/* # Decode inputs */
    /* k = decode_scalar25519(scalar_bytes) */
    /* u = decode_u_coordinate(u_bytes) */

    /* # Initialize */
    /* x1 = u */
    /* x2 = 1 */
    /* z2 = 0 */
    /* x3 = u */
    /* z3 = 1 */
    /* swap = 0 */

    /* # Montgomery ladder */
    /* for t in reversed(range(255)): */
        /* k_t = (k >> t) & 1 */
        /* swap ^= k_t */

        /* x2, x3 = cswap(swap, x2, x3) */
        /* z2, z3 = cswap(swap, z2, z3) */
        /* swap = k_t */

        /* A  = (x2 + z2) % P */
        /* AA = (A * A) % P */
        /* B  = (x2 - z2) % P */
        /* BB = (B * B) % P */
        /* E  = (AA - BB) % P */
        /* C  = (x3 + z3) % P */
        /* D  = (x3 - z3) % P */
        /* DA = (D * A) % P */
        /* CB = (C * B) % P */

        /* x3 = ((DA + CB) ** 2) % P */
        /* z3 = (x1 * ((DA - CB) ** 2 % P)) % P */
        /* x2 = (AA * BB) % P */
        /* z2 = (E * (AA + A24 * E % P)) % P */

    /* # Final swap */
    /* x2, x3 = cswap(swap, x2, x3) */
    /* z2, z3 = cswap(swap, z2, z3) */

    /* # Affine conversion: x2 / z2 */
    /* result = (x2 * pow(z2, P - 2, P)) % P */

    /* return encode_u_coordinate(result) */
}

int test_x25519(u8* data) {
	TODO("implement me.");
	return -KOCKET_TODO;
}

#endif //_X25519_H_

