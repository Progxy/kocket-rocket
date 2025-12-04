#ifndef _ED25519_H_
#define _ED25519_H_

#define _KOCKET_SPECIAL_TYPE_SUPPORT_
#define _KOCKET_UTILS_IMPLEMENTATION_
#define _KOCKET_PRINTING_UTILS_
#include "../kocket_utils.h"
#include "./chacha20.h"
#include "./sha512.h"
#include "./ecm_ops.h"

/* Reference: [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) */

// TODO: Refactor/Clean the code...

typedef u8 Ed25519Key[32];
typedef u8 Ed25519Signature[64];

#define PRINT_KEY(key) print_key(#key, key)
void print_key(const char* name, const Ed25519Key key) {
	printf("%s: ", name);
	for (int i = 31; i >= 0; --i) printf("%02X", key[i]);
	printf("\n");
	return;
}

#define PRINT_SIGNATURE(signature) print_signature(#signature, signature)
void print_signature(const char* name, const Ed25519Signature signature) {
	printf("%s: ", name);
	for (int i = 63; i >= 0; --i) printf("%02X", signature[i]);
	printf("\n");
	return;
}

void generate_priv_key(Ed25519Key priv_key) {
	u8 random_data[64] = {0};
	cha_cha20(random_data);
	mem_cpy(priv_key, random_data, sizeof(Ed25519Key));
	return;
}

int generate_pub_key(Ed25519Key pub_key, Ed25519Key priv_key) {
	int err = 0;
	sha512_t h = {0};

	KOCKET_BE_CONVERT(priv_key, sizeof(Ed25519Key));
	if ((err = sha512(priv_key, sizeof(Ed25519Key), (u64*) h))) return err;

	mem_cpy(pub_key, h, sizeof(Ed25519Key));
	
	// Prune the buffer
	pub_key[0] &= ~(0x07);
	pub_key[31] &= ~(0x80);
	pub_key[31] |= 0x40;
	
	PRINT_KEY(pub_key);
	
	ECMPoint temp_point = {0};
	ECMScalar pub_key_scalar = ptr_to_scalar(pub_key, sizeof(Ed25519Key));
	mul_point(ptr_to_scalar(pub_key, sizeof(Ed25519Key)), (ECMPoint*) &base_point, &temp_point);
	ECM_PRINT_POINT(temp_point);
	compress_point(&pub_key_scalar, &temp_point);
	
	ECM_PRINT_SCALAR(pub_key_scalar);

	return KOCKET_NO_ERROR;
}

int sign(Ed25519Signature signature, Ed25519Key priv_key, Ed25519Key pub_key, u8* data, u64 len) {
	if ((data == NULL && len != 0) || signature == NULL) return -KOCKET_INVALID_PARAMETERS;
	
	int err = 0;
	sha512_t h = {0};
	if ((err = sha512_le(priv_key, sizeof(Ed25519Key), (u64*) h))) return err;
	
	u64 r_len = 32;
	u8* r = concat(4, &r_len, h + 32, 32, data, len);
	if (r == NULL) return -KOCKET_IO_ERROR;
	
	sha512_t hashed_data = {0};
	if ((err = sha512_le(r, r_len, (u64*) hashed_data))) {
		KOCKET_SAFE_FREE(r);
		return err;
	}
	
	KOCKET_SAFE_FREE(r);
	
	// For efficiency, do this by first reducing r modulo L, the group order of B.
	ECMScalar hashed_data_scalar = ecm_mod(ptr_to_scalar(hashed_data, sizeof(hashed_data)), L);
	
	char temp_str[1024] = {0};
	printf("r: %s\n", to_hex_str(hashed_data_scalar.data, sizeof(hashed_data_scalar.data), temp_str, FALSE));
	mem_set(temp_str, 0, 1024);

	ECMScalar R = {0};
	ECMPoint temp_point = {0};
	compress_point(&R, mul_point(hashed_data_scalar, (ECMPoint*) &base_point, &temp_point));

	u64 K_len = 0;
	// TODO: Find a way to macro function calculate the count of parameters
	u8* K = concat(6, &K_len, R.data, sizeof(R), pub_key, sizeof(Ed25519Key), data, len);
	if (K == NULL) return -KOCKET_IO_ERROR;

	sha512_t k = {0};
	if ((err = sha512(K, K_len, (u64*) k))) {
		KOCKET_SAFE_FREE(K);
		return err;
	}

	// For efficiency, again reduce k modulo L first.
	ECMScalar k_scalar = ecm_mod(ptr_to_scalar(k, sizeof(k)), L);
	ECMScalar S = ecm_mod(ecm_add(hashed_data_scalar, ecm_mul(k_scalar, ptr_to_scalar(h, sizeof(Ed25519Key)))), L);

	mem_cpy(signature, R.data, sizeof(Ed25519Key));
	mem_cpy(signature + sizeof(Ed25519Key), S.data, sizeof(Ed25519Key));
	
	KOCKET_SAFE_FREE(K);
	ecm_clean_temp();

	return KOCKET_NO_ERROR;
}

int verify_signature(Ed25519Key pub_key, Ed25519Signature signature, u8* data, u64 len) {
	if ((data == NULL && len != 0) || signature == NULL) return -KOCKET_INVALID_PARAMETERS;

	ECMScalar R = {0};
	ECMScalar S = {0};
	mem_cpy(R.data, signature, sizeof(ECMScalar));
	mem_cpy(S.data, signature + sizeof(ECMScalar), sizeof(ECMScalar));
	
	if (ecm_is_gt_eq(S, L)) {
		WARNING_LOG("Failed to decode the signature as: S >= L");
		return -KOCKET_INVALID_SIGNATURE;
	}

	ECMCoord* decoded_r = decode_point(R);
	if (decoded_r == NULL) return -KOCKET_INVALID_SIGNATURE;

	ECMCoord* decoded_A = decode_point(ptr_to_scalar(pub_key, sizeof(Ed25519Key)));
	if (decoded_A == NULL) {
		KOCKET_SAFE_FREE(decoded_r);
		return -KOCKET_INVALID_SIGNATURE;
	}

	int err = 0;
	u64 K_len = 0;
	// TODO: Find a way to macro function calculate the count of parameters
	u8* K = concat(6, &K_len, R.data, sizeof(R), pub_key, sizeof(Ed25519Key), data, len);
	if (K == NULL) {
		KOCKET_SAFE_FREE(decoded_r);
		KOCKET_SAFE_FREE(decoded_A);
		return -KOCKET_IO_ERROR;
	}

	sha512_t k = {0};
	if ((err = sha512(K, K_len, (u64*) k))) {
		KOCKET_SAFE_FREE(decoded_r);
		KOCKET_SAFE_FREE(decoded_A);
		KOCKET_SAFE_FREE(K);
		return err;
	}

	// Check the group equation.  
	ECMPoint temp_point = {0};
	ECMPoint S_B = {0};
	mul_point(eight, mul_point(S, (ECMPoint*) &base_point, &S_B), &S_B);
	ECMPoint k_A = {0};
	mul_point(eight, mul_point(ptr_to_scalar(k, sizeof(k)), coord_to_point(decoded_A, &temp_point), &k_A), &k_A);
   	ECMPoint R_k_A = {0};
	add_point(mul_point(eight, coord_to_point(decoded_r, &temp_point), &R_k_A), &k_A, TRUE);

	if (!is_point_eq(&S_B, &R_k_A)) {
		KOCKET_SAFE_FREE(decoded_r);
		KOCKET_SAFE_FREE(decoded_A);
		KOCKET_SAFE_FREE(K);

		WARNING_LOG("Failed to decode the signature as: [8][S]B = [8]R + [8][k]A', is not true");
		return -KOCKET_INVALID_SIGNATURE;
	}

	KOCKET_SAFE_FREE(decoded_r);
	KOCKET_SAFE_FREE(decoded_A);
	KOCKET_SAFE_FREE(K);

	return KOCKET_NO_ERROR;
}

/// TEST CONSTANTS
static Ed25519Key SECRET_KEY_LE = {
    0x60, 0x7f, 0xae, 0x1c, 0x03, 0xac, 0x3b, 0x70,
    0x19, 0x69, 0x32, 0x7b, 0x69, 0xc5, 0x49, 0x44,
    0xc4, 0x2c, 0xec, 0x92, 0xf4, 0x4a, 0x84, 0xba,
    0x60, 0x5a, 0xfd, 0xef, 0x9d, 0xb1, 0x61, 0x9d
};

static Ed25519Key SECRET_KEY_BE = {
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
	0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
	0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
};

static Ed25519Key PUBLIC_KEY_BE = {
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};

int test_ed25519(u8* data, u64 len) {
	int err = 0;
	char temp_str[1024] = {0};
	/* Ed25519Key priv_key = {0}; */
	/* generate_priv_key(priv_key); */
	
	/* printf("Private Key: %s\n", to_hex_str(priv_key, sizeof(Ed25519Key), temp_str, FALSE)); */
	/* mem_set(temp_str, 0, 1024); */

	Ed25519Key pub_key = {0};
	if ((err = generate_pub_key(pub_key, SECRET_KEY_LE))) {
		ERROR_LOG("Failed to generate the public key.", kocket_status_str[-err]);
		return err;
	}
	
	printf("Public Key: %s\n", to_hex_str(pub_key, sizeof(Ed25519Key), temp_str, FALSE));
	mem_set(temp_str, 0, 1024);

	/* Ed25519Signature signature = {0}; */
	/* if ((err = sign(signature, SECRET_KEY_BE, PUBLIC_KEY_BE, NULL, 0))) { */
	/* 	ERROR_LOG("Failed to sign.", kocket_status_str[-err]); */
	/* 	return err; */
	/* } */

	/* printf("Signature: %s\n", to_hex_str(signature, sizeof(Ed25519Signature), temp_str, FALSE)); */
	/* mem_set(temp_str, 0, 1024); */
	
	/* if (verify_signature(pub_key, signature, NULL, 0)) { */
	/* 	printf("Failed to verify the signature.\n"); */
	/* 	return -KOCKET_INVALID_SIGNATURE; */
	/* } */
	
	return KOCKET_NO_ERROR;
}

#endif //_ED25519_H_

