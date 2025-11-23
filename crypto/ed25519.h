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

void generate_priv_key(Ed25519Key priv_key) {
	u8 random_data[64] = {0};
	cha_cha20(random_data);
	mem_cpy(priv_key, random_data, sizeof(Ed25519Key));
	return;
}

int generate_pub_key(Ed25519Key pub_key, Ed25519Key priv_key) {
	int err = 0;
	u8 h[64] = {0};

	// TODO: Maybe needed to convert the sha512 digest back into little endian
	if ((err = sha512(priv_key, sizeof(Ed25519Key), (u64*) h))) return err;

	// Prune the buffer
	h[0] &= ~(0x07);
	h[31] &= ~(0x80);
	h[31] |= 0x40;
	
	mem_cpy(pub_key, h, sizeof(Ed25519Key));
	
	compress_point(ptr_to_scalar(pub_key, sizeof(Ed25519Key)), mul_point(ptr_to_scalar(pub_key, sizeof(Ed25519Key)), (ECMPoint*) &base_point), TRUE);

	return KOCKET_NO_ERROR;
}

int sign(Ed25519Signature signature, Ed25519Key priv_key, Ed25519Key pub_key, u8* data, u64 len) {
	if (data == NULL || len == 0 || signature == NULL) return -KOCKET_INVALID_PARAMETERS;
	int err = 0;

	u8 h[64] = {0};
	if ((err = sha512(priv_key, sizeof(Ed25519Key), (u64*) h))) return err;

	u8 hashed_data[64] = {0};
	// TODO: concatenate the prefix
	if ((err = sha512(data, len, (u64*) hashed_data))) return err;
	
	// For efficiency, do this by first reducing r modulo L, the group order of B.
	ECMScalar hashed_data_scalar = ecm_mod(ptr_to_scalar(hashed_data, sizeof(hashed_data)), L);
	ECMScalar R = { 0 };
	compress_point(R, mul_point(hashed_data_scalar, (ECMPoint*) &base_point), TRUE);

	u64 K_len = 0;
	// TODO: Find a way to macro function calculate the count of parameters
	u8* K = concat(6, &K_len, R.data, sizeof(R), pub_key, sizeof(Ed25519Key), data, len);
	if (K == NULL) return -KOCKET_IO_ERROR;
	
	u8 k[64] = {0};
	if ((err = sha512(K, K_len, (u64*) k))) return err;

	// For efficiency, again reduce k modulo L first.
	ECMScalar k_scalar = ecm_mod(ptr_to_scalar(k, sizeof(k)),L);
	ECMScalar S = ecm_mod(ecm_add(hashed_data_scalar, ecm_mul(k_scalar, ptr_to_scalar(priv_key, sizeof(Ed25519Key)))), L);

	mem_cpy(signature, S.data, sizeof(Ed25519Key));
	mem_cpy(signature + sizeof(Ed25519Key), R.data, sizeof(Ed25519Key));

	return KOCKET_NO_ERROR;
}

int verify_signature(Ed25519Key pub_key, Ed25519Signature signature, u8* data, u64 len) {
	if (data == NULL || len == 0 || signature == NULL) return -KOCKET_INVALID_PARAMETERS;
	
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
	if (decoded_A == NULL) return -KOCKET_INVALID_SIGNATURE;
	
	int err = 0;
	u64 K_len = 0;
	// TODO: Find a way to macro function calculate the count of parameters
	u8* K = concat(6, &K_len, R.data, sizeof(R), pub_key, sizeof(Ed25519Key), data, len);
	if (K == NULL) return -KOCKET_IO_ERROR;
	
	u8 k[64] = {0};
	if ((err = sha512(K, K_len, (u64*) k))) return err;

	// Check the group equation.  
	ECMPoint* S_B = mul_point(eight, mul_point(S, (ECMPoint*) &base_point));
	ECMPoint* k_A = mul_point(eight, mul_point(ptr_to_scalar(k, sizeof(k)), coord_to_point(decoded_A)));
   	ECMPoint* R_k_A = add_point(mul_point(eight, coord_to_point(decoded_r)), k_A, FALSE);

	if (!is_point_eq(S_B, R_k_A)) {
		KOCKET_SAFE_FREE(S_B);
		KOCKET_SAFE_FREE(R_k_A);

		WARNING_LOG("Failed to decode the signature as: [8][S]B = [8]R + [8][k]A', is not true");
		return -KOCKET_INVALID_SIGNATURE;
	}

	KOCKET_SAFE_FREE(S_B);
	KOCKET_SAFE_FREE(R_k_A);

	return KOCKET_NO_ERROR;
}

int test_ed25519(u8* data, u64 len) {
	int err = 0;
	char temp_str[1024] = {0};
	Ed25519Key priv_key = {0};
	generate_priv_key(priv_key);
	
	printf("Private Key: %s\n", to_hex_str(priv_key, sizeof(Ed25519Key), temp_str, FALSE));
	mem_set(temp_str, 0, 1024);

	Ed25519Key pub_key = {0};
	if ((err = generate_pub_key(pub_key, priv_key))) {
		ERROR_LOG("Failed to generate the public key.", kocket_status_str[-err]);
		return err;
	}
	
	printf("Public Key: %s\n", to_hex_str(pub_key, sizeof(Ed25519Key), temp_str, FALSE));
	mem_set(temp_str, 0, 1024);

	Ed25519Signature signature = {0};
	if ((err = sign(signature, priv_key, pub_key, data, len))) {
		ERROR_LOG("Failed to sign.", kocket_status_str[-err]);
		return err;
	}

	printf("Signature: %s\n", to_hex_str(signature, sizeof(Ed25519Signature), temp_str, FALSE));
	mem_set(temp_str, 0, 1024);
	
	if (verify_signature(pub_key, signature, data, len)) {
		printf("Failed to verify the signature.\n");
		return -KOCKET_INVALID_SIGNATURE;
	}
	
	return KOCKET_NO_ERROR;
}

#endif //_ED25519_H_

