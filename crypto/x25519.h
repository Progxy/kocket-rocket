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

// TODO: Refactor the code, and introduce some error handling.
typedef u8 x25519Scalar[32];

static const x25519Scalar x25519_base_point = {
	0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define PRINT_X25519_SCALAR(scalar) print_scalar(#scalar, scalar)
static void print_scalar(const char* name, const x25519Scalar scalar) {
	printf("%s: ", name);
	for (int i = 31; i >= 0; --i) printf("%02X", scalar[i]);
	printf("\n");
	return;
}

static void decode_scalar25519(x25519Scalar k, const x25519Scalar scalar) {
	mem_cpy(k, scalar, sizeof(x25519Scalar));
	k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;
    return;
}

// TODO: Could be that the encode/decode also switch from little endian to big
// endian, check this if encountering errors
#define encode_u_coordinate decode_u_coordinate
static void decode_u_coordinate(const x25519Scalar u, x25519Scalar d_u) {
	ECMScalar u_s = ptr_to_scalar((u8*) u, sizeof(x25519Scalar));
	ECMScalar decoded_u = ecm_mod(u_s, p);
	ecm_clean_temp();
	mem_cpy(d_u, decoded_u.data, sizeof(x25519Scalar));
	return;
}

static void and_scalar(x25519Scalar scalar, const x25519Scalar a, const x25519Scalar b) {
	for (unsigned int i = 0; i < 32; ++i) scalar[i] = a[i] & b[i];
	return;
}

static void xor_scalar(x25519Scalar scalar, const x25519Scalar a, const x25519Scalar b) {
	for (unsigned int i = 0; i < 32; ++i) scalar[i] = a[i] ^ b[i];
	return;
}

// TODO: Implement me
static void neg_scalar(x25519Scalar scalar, const x25519Scalar a) {
	u64 carry = 0;
	for (unsigned int i = 0; i < 4; ++i) {
		carry = _subborrow_u64(carry, ((u64*) scalar)[i], ((u64*) a)[i], ((u64*) scalar) + i);
	}
	return;
}

static void cswap(const x25519Scalar swap, x25519Scalar x2, x25519Scalar x3) {
    x25519Scalar mask = {0};
	neg_scalar(mask, swap);

    x25519Scalar t = {0};
    x25519Scalar temp = {0};
	xor_scalar(temp, x2, x3);
	and_scalar(t, mask, temp);
    
	xor_scalar(x2, x2, t);
	xor_scalar(x3, x3, t);

	return;
}

static void clamp_scalar(x25519Scalar k, const u8* k_data) {
	mem_cpy(k, k_data, sizeof(x25519Scalar));
    k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;
	return;
}

#define SCALAR_BIT(val, n) ((((val)[(((n) - ((n) % 8)) / 8)]) >> ((n) % 8)) & 0x01)
void x25519(x25519Scalar res, const x25519Scalar scalar_bytes, const x25519Scalar u_bytes) {
	// Decode inputs
    x25519Scalar k = {0};
	decode_scalar25519(k, scalar_bytes);
    x25519Scalar u = {0};
	decode_u_coordinate(u_bytes, u);

    // Initialize
    x25519Scalar x1   = {0};
    x25519Scalar x2   = {1};
    x25519Scalar z2   = {0};
    x25519Scalar x3   = {0};
    x25519Scalar z3   = {1};
    x25519Scalar swap = {0};

	mem_cpy(x1, u, sizeof(x25519Scalar));
	mem_cpy(x3, u, sizeof(x25519Scalar));

    // Montgomery ladder
    for (int t = 254; t >= 0; --t) {
        x25519Scalar k_t = {0};
		k_t[0] = SCALAR_BIT(k, t);
		xor_scalar(swap, swap, k_t);

        cswap(swap, x2, x3);
        cswap(swap, z2, z3);
        mem_cpy(swap, k_t, sizeof(x25519Scalar));

		ECMScalar x3_scalar = ptr_to_scalar(x3, sizeof(x25519Scalar));
		ECMScalar z3_scalar = ptr_to_scalar(z3, sizeof(x25519Scalar));
		ECMScalar x2_scalar = ptr_to_scalar(x2, sizeof(x25519Scalar));
		ECMScalar z2_scalar = ptr_to_scalar(z2, sizeof(x25519Scalar));

        ECMScalar A  = ecm_add(x2_scalar, z2_scalar);
        ECMScalar AA = ecm_mul(A, A);
        ECMScalar B  = ecm_sub(x2_scalar, z2_scalar);
        ECMScalar BB = ecm_mul(B, B);
        ECMScalar E  = ecm_sub(AA, BB);
        ECMScalar C  = ecm_add(x3_scalar, z3_scalar);
        ECMScalar D  = ecm_sub(x3_scalar, z3_scalar);
        ECMScalar DA = ecm_mul(D, A);
        ECMScalar CB = ecm_mul(C, B);

		ECMScalar x1_scalar = ptr_to_scalar(x1, sizeof(x25519Scalar));
        ECMScalar x3_final = ecm_pow(ecm_add(DA, CB), 2);
        ECMScalar z3_final = ecm_mul(x1_scalar, ecm_pow(ecm_sub(DA, CB), 2));
        ECMScalar x2_final = ecm_mul(AA, BB);
        ECMScalar z2_final = ecm_mul(E, ecm_add(AA, ecm_mul(a24, E)));
		
		mem_cpy(x3, x3_final.data, sizeof(x25519Scalar));
		mem_cpy(z3, z3_final.data, sizeof(x25519Scalar));
		mem_cpy(x2, x2_final.data, sizeof(x25519Scalar));
		mem_cpy(z2, z2_final.data, sizeof(x25519Scalar));

		ecm_clean_temp();
	}

    // Final swap
    cswap(swap, x2, x3);
    cswap(swap, z2, z3);

   	// Affine conversion: x2 / z2
    ECMScalar result = ecm_mul(ptr_to_scalar(x2, sizeof(x25519Scalar)), ecm_spow(ptr_to_scalar(z2, sizeof(x25519Scalar)), p_minus_2));
	
	x25519Scalar temp = {0};
	mem_cpy(temp, result.data, sizeof(x25519Scalar));
    encode_u_coordinate(temp, res);
	
	return;
}

static void random_32_bytes(u8 random_bytes[32]) {
	u8 random_data[64] = {0};
	mem_cpy(random_bytes, cha_cha20(random_data), 32);
	return;
}

// TODO: Testing vector
static const u8 RECIPIENT_PRIV_RAW[32] = {
	0x58, 0xD3, 0xDB, 0xA2, 0x8E, 0x0B, 0x62, 0x25, 
	0x7B, 0xF4, 0x45, 0x37, 0xB6, 0x81, 0xC4, 0xA2, 
	0x90, 0x1A, 0xF6, 0x78, 0xB2, 0x8A, 0x88, 0xD8, 
	0x17, 0x02, 0x9A, 0x37, 0xCE, 0x4B, 0xEB, 0x60
};

static const u8 SENDER_EPH_PRIV_RAW[32] = {
	0x80, 0x7F, 0xA8, 0x29, 0x94, 0x70, 0x3A, 0x7C, 
	0x19, 0xB8, 0x1E, 0x29, 0x03, 0x3E, 0x7E, 0xFA, 
	0xB6, 0xF7, 0x39, 0x38, 0xB8, 0x01, 0xF1, 0xD4,
   	0xB5, 0x12, 0x84, 0xEE, 0x1B, 0xEC, 0xEC, 0x7B
};

static const x25519Scalar RECIPIENT_PUB = {
	0x66, 0xCA, 0xE6, 0x13, 0x6E, 0x7A, 0xE8, 0x2F,
   	0x67, 0x71, 0x5A, 0x37, 0x16, 0x2E, 0x14, 0xC2, 
	0xCF, 0x51, 0x5C, 0x0A, 0x95, 0x13, 0x56, 0x40, 
	0xE9, 0x32, 0x0C, 0xB4, 0x12, 0x08, 0xC7, 0x3D
};

static const x25519Scalar SENDER_PUB = {
	0x26, 0x20, 0xFC, 0x1D, 0xAA, 0x0D, 0x73, 0xC2, 
	0xB0, 0x09, 0xF8, 0xCD, 0x99, 0xAA, 0xC8, 0x7F, 
	0xC5, 0xA1, 0x50, 0xD8, 0x6D, 0xC7, 0xFA, 0xB5, 
	0xAA, 0x39, 0xFB, 0x8B, 0x6F, 0x39, 0x89, 0x88
};

static const x25519Scalar SHARED = {
	0x42, 0x85, 0x18, 0x38, 0x56, 0xD1, 0x11, 0xB4, 
	0xB1, 0x60, 0x7D, 0x13, 0xE7, 0xAF, 0x5D, 0xAD, 
	0x26, 0x63, 0x13, 0x09, 0x8A, 0xF5, 0x75, 0x88, 
	0x3C, 0x30, 0x87, 0x71, 0xC8, 0xF7, 0xB1, 0x70
};

int test_x25519(bool test) {
    // Recipient static private key
    x25519Scalar recipient_priv = {0};
    
	if (!test) {
		u8 recipient_priv_raw[32] = {0};
		random_32_bytes(recipient_priv_raw);
		clamp_scalar(recipient_priv, recipient_priv_raw);
	} else {
		clamp_scalar(recipient_priv, RECIPIENT_PRIV_RAW);
	}

    // Recipient public key
    x25519Scalar recipient_pub = {0};
	x25519(recipient_pub, recipient_priv, x25519_base_point);

	if (test) {
		if (mem_cmp(recipient_pub, RECIPIENT_PUB, sizeof(x25519Scalar))) {
			PRINT_X25519_SCALAR(recipient_pub);
			PRINT_X25519_SCALAR(RECIPIENT_PUB);
			WARNING_LOG("Mismatch in recipient_pub.");
			return -KOCKET_INVALID_SHARED_SECRET;
		}
	}

    printf("=== Recipient static keypair ===\n");
    PRINT_X25519_SCALAR(recipient_priv);
    PRINT_X25519_SCALAR(recipient_pub);
    printf("\n");
    
    // Sender ephemeral private key
    x25519Scalar sender_eph_priv = {0};
    if (!test) {
		u8 sender_eph_priv_raw[32] = {0};
		random_32_bytes(sender_eph_priv_raw);
		clamp_scalar(sender_eph_priv, sender_eph_priv_raw);
	} else {
		clamp_scalar(sender_eph_priv, SENDER_EPH_PRIV_RAW);
	}

    // Sender ephemeral public key
    x25519Scalar sender_eph_pub = {0};
	x25519(sender_eph_pub, sender_eph_priv, x25519_base_point);
	
	if (test) {
		if (mem_cmp(sender_eph_pub, SENDER_PUB, sizeof(x25519Scalar))) {
			PRINT_X25519_SCALAR(sender_eph_pub);
			PRINT_X25519_SCALAR(SENDER_PUB);
			WARNING_LOG("Mismatch in sender_eph_pub.");
			return -KOCKET_INVALID_SHARED_SECRET;
		}
	}

    printf("=== Sender ephemeral keypair ===\n");
    PRINT_X25519_SCALAR(sender_eph_priv);
    PRINT_X25519_SCALAR(sender_eph_pub);
    printf("\n");

    x25519Scalar sender_shared = {0};
	x25519(sender_shared, sender_eph_priv, recipient_pub);

	if (test) {
		if (mem_cmp(sender_shared, SHARED, sizeof(x25519Scalar))) {
			PRINT_X25519_SCALAR(sender_shared);
			PRINT_X25519_SCALAR(SHARED);
			WARNING_LOG("Mismatch betweeen sender_shared and shared.");
			return -KOCKET_INVALID_SHARED_SECRET;
		}
	}

    printf("=== Sender computed shared secret ===\n");
    PRINT_X25519_SCALAR(sender_shared);
    printf("\n");

    x25519Scalar recipient_shared = {0};
	x25519(recipient_shared, recipient_priv, sender_eph_pub);
	
	if (test) {
		if (mem_cmp(recipient_shared, SHARED, sizeof(x25519Scalar))) {
			PRINT_X25519_SCALAR(recipient_shared);
			PRINT_X25519_SCALAR(SHARED);
			WARNING_LOG("Mismatch between recipient_shared and shared.");
			return -KOCKET_INVALID_SHARED_SECRET;
		}
	}

    printf("=== Recipient computed shared secret ===\n");
    PRINT_X25519_SCALAR(recipient_shared);
    printf("\n");

	if (!test && mem_cmp(sender_shared, recipient_shared, sizeof(x25519Scalar))) {
		WARNING_LOG("Mismatch between shared secrets.");
		return -KOCKET_INVALID_SHARED_SECRET;
	}

    printf("=== Equality check ===\n");
    printf("Shared secrets match.\n");
	
	return KOCKET_NO_ERROR;
}

#endif //_X25519_H_

