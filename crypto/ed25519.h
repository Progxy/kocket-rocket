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
	KOCKET_BE_CONVERT(priv_key, sizeof(Ed25519Key));

	mem_cpy(pub_key, h, sizeof(Ed25519Key));
	
	// Prune the buffer
	pub_key[0] &= ~(0x07);
	pub_key[31] &= ~(0x80);
	pub_key[31] |= 0x40;
	
	ECMPoint temp_point = {0};
	ECMScalar pub_key_scalar = ptr_to_scalar(pub_key, sizeof(Ed25519Key));
	mul_point(ptr_to_scalar(pub_key, sizeof(Ed25519Key)), (ECMPoint*) &base_point, &temp_point);
	compress_point(&pub_key_scalar, &temp_point);
	
	mem_cpy(pub_key, pub_key_scalar.data, sizeof(Ed25519Key));

	KOCKET_BE_CONVERT(pub_key, sizeof(Ed25519Key));

	return KOCKET_NO_ERROR;
}

int sign(Ed25519Signature signature, Ed25519Key priv_key, Ed25519Key pub_key, u8* data, u64 len) {
	if ((data == NULL && len != 0) || signature == NULL) return -KOCKET_INVALID_PARAMETERS;
	
	int err = 0;
	sha512_t h = {0};
	KOCKET_BE_CONVERT(priv_key, sizeof(Ed25519Key));
	if ((err = sha512(priv_key, sizeof(Ed25519Key), (u64*) h))) return err;
	KOCKET_BE_CONVERT(priv_key, sizeof(Ed25519Key));
	
	Ed25519Key a = {0};
	mem_cpy(a, h, sizeof(Ed25519Key));
	
	// Prune the buffer
	a[0] &= ~(0x07);
	a[31] &= ~(0x80);
	a[31] |= 0x40;
	
	u64 r_len = 0;
	u8* r = concat(4, &r_len, data, len, h + 32, 32);
	if (r == NULL) return -KOCKET_IO_ERROR;
	
	sha512_t hashed_data = {0};
	if ((err = sha512(r, r_len, (u64*) hashed_data))) {
		KOCKET_SAFE_FREE(r);
		return err;
	}
	
	KOCKET_SAFE_FREE(r);
	
	// For efficiency, do this by first reducing r modulo L, the group order of B.
	ECMScalar hashed_data_scalar = ecm_mod(ptr_to_scalar(hashed_data, sizeof(hashed_data)), L);

	ECMScalar R = {0};
	ECMPoint temp_point = {0};
	mul_point(hashed_data_scalar, (ECMPoint*) &base_point, &temp_point);
	compress_point(&R, &temp_point);
	KOCKET_BE_CONVERT(R.data, sizeof(Ed25519Key));

	u64 K_len = 0;
	// TODO: Find a way to macro function calculate the count of parameters
	u8* K = concat(6, &K_len, data, len, pub_key, sizeof(Ed25519Key), R.data, sizeof(Ed25519Key));
	if (K == NULL) return -KOCKET_IO_ERROR;

	sha512_t k = {0};
	KOCKET_BE_CONVERT(K, K_len);
	if ((err = sha512(K, K_len, (u64*) k))) {
		KOCKET_SAFE_FREE(K);
		return err;
	}
	
	KOCKET_SAFE_FREE(K);

	// For efficiency, again reduce k modulo L first.
	ECMScalar S = {0};
	u8* temp_data[SCALAR_SIZE * 2 + 8] = {0};
	u8* k_data[SCALAR_SIZE] = {0};
	BigNum ke_num  = POS_STATIC_BIG_NUM(k, sizeof(k));
	BigNum k_num  = POS_STATIC_BIG_NUM(k_data, sizeof(Ed25519Key));
	BigNum a_num  = POS_STATIC_BIG_NUM(a, sizeof(Ed25519Key));
	BigNum l_num  = POS_STATIC_BIG_NUM(L.data, SCALAR_SIZE);
	BigNum hd_num = POS_STATIC_BIG_NUM(hashed_data_scalar.data, SCALAR_SIZE);
	BigNum s_num  = POS_STATIC_BIG_NUM(S.data, SCALAR_SIZE);
	BigNum res    = POS_STATIC_BIG_NUM(temp_data, SCALAR_SIZE * 2 + 8);
	
	if (__chonky_mod(&k_num, &ke_num, &l_num) == NULL) return -KOCKET_IO_ERROR;
	if (__chonky_mul_s(&res, &k_num, &a_num) == NULL) return -KOCKET_IO_ERROR;
	__chonky_add(&res, &hd_num, &res);
	if (__chonky_mod(&s_num, &res, &l_num) == NULL) return -KOCKET_IO_ERROR;

	KOCKET_BE_CONVERT(R.data, sizeof(Ed25519Key));
	mem_cpy(signature, R.data, sizeof(Ed25519Key));
	mem_cpy(signature + sizeof(Ed25519Key), S.data, sizeof(Ed25519Key));
	
	KOCKET_BE_CONVERT(signature, sizeof(Ed25519Signature));

	return KOCKET_NO_ERROR;
}

int verify_signature(Ed25519Key pub_key, Ed25519Signature signature, u8* data, u64 len) {
	if ((data == NULL && len != 0) || signature == NULL) return -KOCKET_INVALID_PARAMETERS;

	ECMPoint decoded_A = {0};
	if (decode_point(ptr_to_scalar(pub_key, sizeof(Ed25519Key)), &decoded_A) == NULL) {
		return -KOCKET_INVALID_SIGNATURE;
	}


	ECMScalar R = {0};
	ECMScalar S = {0};
	mem_cpy(S.data, signature, sizeof(Ed25519Key));
	mem_cpy(R.data, signature + sizeof(Ed25519Key), sizeof(Ed25519Key));
	
	if (ecm_is_gt_eq(S, L)) {
		WARNING_LOG("Failed to decode the signature as: S >= L");
		return -KOCKET_INVALID_SIGNATURE;
	}

	ECMPoint decoded_r = {0};
	if (decode_point(R, &decoded_r) == NULL) return -KOCKET_INVALID_SIGNATURE;

	KOCKET_BE_CONVERT(S.data, sizeof(Ed25519Key));

	int err = 0;
	u64 K_len = 0;
	u8* K = concat(6, &K_len, data, len, pub_key, sizeof(Ed25519Key), R.data, sizeof(Ed25519Key));
	if (K == NULL) return -KOCKET_IO_ERROR;

	sha512_t k = {0};
	KOCKET_BE_CONVERT(K, K_len);

	if ((err = sha512(K, K_len, (u64*) k))) {
		KOCKET_SAFE_FREE(K);
		return err;
	}
	
	KOCKET_SAFE_FREE(K);
	
	// Calculate k % L for optimization
	u8 k_data[SCALAR_SIZE] = {0};
	BigNum ke_num = POS_STATIC_BIG_NUM(k, sizeof(k));
	BigNum k_num = POS_STATIC_BIG_NUM(k_data, SCALAR_SIZE);
	BigNum l_num  = POS_STATIC_BIG_NUM(L.data, SCALAR_SIZE);
	if (__chonky_mod(&k_num, &ke_num, &l_num) == NULL) return -KOCKET_IO_ERROR;
	
	// Check the group equation.  
	ECMPoint S_B = {0};
	mul_point(S, (ECMPoint*) &base_point, &S_B);
	
	ECMPoint h_A = {0};
	mul_point(ptr_to_scalar(k_data, SCALAR_SIZE), &decoded_A, &h_A);
   	
	add_point(&decoded_r, &h_A, TRUE);

	if (!is_point_eq(&S_B, &decoded_r)) {
		WARNING_LOG("Failed to decode the signature as: [8][S]B = [8]R + [8][k]A', is not true");
		return -KOCKET_INVALID_SIGNATURE;
	}

	return KOCKET_NO_ERROR;
}

/// TEST CONSTANTS
static Ed25519Key SECRET_KEY_LE = {
    0x60, 0x7f, 0xae, 0x1c, 0x03, 0xac, 0x3b, 0x70,
    0x19, 0x69, 0x32, 0x7b, 0x69, 0xc5, 0x49, 0x44,
    0xc4, 0x2c, 0xec, 0x92, 0xf4, 0x4a, 0x84, 0xba,
    0x60, 0x5a, 0xfd, 0xef, 0x9d, 0xb1, 0x61, 0x9d
};

static Ed25519Key PUBLIC_KEY_LE = {
	0x1A, 0x51, 0x07, 0xF7, 0x68, 0x1A, 0x02, 0xAF, 
	0x25, 0x23, 0xA6, 0xDA, 0xF3, 0x72, 0xE1, 0x0E, 
	0x3A, 0x07, 0x64, 0xC9, 0xD3, 0xFE, 0x4B, 0xD5, 
	0xB7, 0x0A, 0xB1, 0x82, 0x01, 0x98, 0x5A, 0xD7
};

static Ed25519Signature SIGNATURE_LE = {
	0x0B, 0x10, 0x7A, 0x8E, 0x43, 0x41, 0x51, 0x65,
   	0x24, 0xBE, 0x5B, 0x59, 0xF0, 0xF5, 0x5B, 0xD2,
   	0x6B, 0xB4, 0xF9, 0x1C, 0x70, 0x39, 0x1E, 0xC6, 
	0xAC, 0x3B, 0xA3, 0x90, 0x15, 0x82, 0xB8, 0x5F, 
	0x55, 0x01, 0x49, 0x22, 0x65, 0xE0, 0x73, 0xD8, 
	0x74, 0xD9, 0xE5, 0xB8, 0x1E, 0x7F, 0x87, 0x84, 
	0x8A, 0x82, 0x6E, 0x80, 0xCC, 0xE2, 0x86, 0x90, 
	0x72, 0xAC, 0x60, 0xC3, 0x00, 0x43, 0x56, 0xE5
};

int test_ed25519(u8* data, u64 len) {
	int err = 0;
	/* Ed25519Key priv_key = SECRET_KEY_LE; */
	Ed25519Key priv_key = {0};
	generate_priv_key(priv_key);
	
	PRINT_KEY(priv_key);

	Ed25519Key pub_key = {0};
	if ((err = generate_pub_key(pub_key, priv_key))) {
		ERROR_LOG("Failed to generate the public key.", kocket_status_str[-err]);
		return err;
	}
	
	PRINT_KEY(pub_key);
	/* PRINT_KEY(PUBLIC_KEY_LE); */

	/* // TODO: Temporary check */
	/* if (mem_cmp(PUBLIC_KEY_LE, pub_key, sizeof(Ed25519Key))) { */
	/* 	WARNING_LOG("publick key does not match"); */
	/* 	return -KOCKET_INVALID_SIGNATURE; */
	/* } */

	Ed25519Signature signature = {0};
	if ((err = sign(signature, priv_key, pub_key, NULL, 0))) {
		ERROR_LOG("Failed to sign.", kocket_status_str[-err]);
		return err;
	}

	PRINT_SIGNATURE(signature);
	/* PRINT_SIGNATURE(SIGNATURE_LE); */
	
	/* // TODO: Temporary check */
	/* if (mem_cmp(SIGNATURE_LE, signature, sizeof(Ed25519Signature))) { */
	/* 	WARNING_LOG("publick key does not match"); */
	/* 	return -KOCKET_INVALID_SIGNATURE; */
	/* } */
	
	if (verify_signature(pub_key, signature, NULL, 0)) {
		printf("Failed to verify the signature.\n");
		return -KOCKET_INVALID_SIGNATURE;
	}
	
	DEBUG_LOG("Successfully passed verification step");

	return KOCKET_NO_ERROR;
}

#endif //_ED25519_H_

