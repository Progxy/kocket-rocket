#ifndef _ED25519_H_
#define _ED25519_H_

#define _KOCKET_SPECIAL_TYPE_SUPPORT_
#define _KOCKET_UTILS_IMPLEMENTATION_
#define _KOCKET_PRINTING_UTILS_
#include "../kocket_utils.h"
#include "./chacha20.h"
#include "./sha512.h"
#include "./chonky_nums.h"

/* Reference: [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) */

// TODO: Refactor/Clean the code...

typedef Ed25519Scalar Ed25519Key;
typedef u8 Ed25519Signature[64];

int generate_pub_key(Ed25519Key pub_key, Ed25519Key priv_key) {
	int err = 0;
	u8 h[64] = {0};

	// TODO: Maybe needed to convert the sha512 digest back into little endian
	if ((err = sha512(priv_key.data, sizeof(Ed25519Key), (u64*) h))) return err;

	// Prune the buffer
	h[0] &= ~(0x07);
	h[31] &= ~(0x80);
	h[31] |= 0x40;
	
	mem_cpy(pub_key.data, h, sizeof(Ed25519Key));
	
	compress_point(pub_key, mul_point(pub_key, (Ed25519Point*) &base_point), TRUE);

	return KOCKET_NO_ERROR;
}

void generate_priv_key(Ed25519Key priv_key) {
	u8 random_data[64] = {0};
	cha_cha20(random_data);
	mem_cpy(priv_key.data, random_data, sizeof(Ed25519Key));
	return;
}

int sign(Ed25519Signature signature, Ed25519Key priv_key, Ed25519Key pub_key, u8* data, u64 len) {
	if (data == NULL || len == 0 || signature == NULL) return -KOCKET_INVALID_PARAMETERS;
	int err = 0;

	u8 h[64] = {0};
	if ((err = sha512(priv_key.data, sizeof(Ed25519Key), (u64*) h))) return err;

	u8 hashed_data[64] = {0};
	// TODO: concatenate the prefix
	if ((err = sha512(data, len, (u64*) hashed_data))) return err;
	
	// For efficiency, do this by first reducing r modulo L, the group order of B.
	Ed25519Scalar hashed_data_scalar = ed25519_mod(ptr_to_scalar(hashed_data), L);
	Ed25519Scalar R = { 0 };
	compress_point(R, mul_point(hashed_data_scalar, (Ed25519Point*) &base_point), TRUE);

	u64 K_len = 0;
	// TODO: Find a way to macro function calculate the count of parameters
	u8* K = concat(6, &K_len, R, sizeof(R), pub_key, sizeof(Ed25519Key), data, len);
	if (K == NULL) return -KOCKET_IO_ERROR;
	
	u8 k[64] = {0};
	if ((err = sha512(K, K_len, (u64*) k))) return err;

	// For efficiency, again reduce k modulo L first.
	Ed25519Scalar k_scalar = ed25519_mod(ptr_to_scalar(k), L);
	Ed25519Scalar S = ed25519_mod(ed25519_add(hashed_data_scalar, ed25519_mul(k_scalar, priv_key)), L);

	mem_cpy(signature, S.data, sizeof(Ed25519Key));
	mem_cpy(signature + sizeof(Ed25519Key), R.data, sizeof(Ed25519Key));

	return KOCKET_NO_ERROR;
}

int verify_signature(Ed25519Key pub_key, Ed25519Signature signature, u8* data, u64 len) {
	if (data == NULL || len == 0 || signature == NULL) return -KOCKET_INVALID_PARAMETERS;
	Ed25519Scalar R = {0};
	Ed25519Scalar S = {0};

	mem_cpy(S.data, signature, sizeof(Ed25519Scalar));
	mem_cpy(R.data, signature + sizeof(Ed25519Scalar), sizeof(Ed25519Scalar));
	
	// TODO: Check the range 0 <= s < L
	
	Ed25519Coord* decoded_r = decode_point(R);
	if (decoded_r == NULL) return -KOCKET_INVALID_POINT;

	Ed25519Coord* decoded_A = decode_point(pub_key);
	if (decoded_A == NULL) return -KOCKET_INVALID_POINT;
	
	int err = 0;
	u64 K_len = 0;
	// TODO: Find a way to macro function calculate the count of parameters
	u8* K = concat(6, &K_len, R, sizeof(R), pub_key, sizeof(Ed25519Key), data, len);
	if (K == NULL) return -KOCKET_IO_ERROR;
	
	u8 k[64] = {0};
	if ((err = sha512(K, K_len, (u64*) k))) return err;

	// TODO: Check the group equation [8][S]B = [8]R + [8][k]A'.  It's
    // sufficient, but not required, to instead check [S]B = R + [k]A'

	return KOCKET_NO_ERROR;
}

int test_ed25519(u8* data, u64 len) {
	int err = 0;
	char temp_str[1024] = {0};
	
	Ed25519Key priv_key = {0};
	generate_priv_key(priv_key);
	
	printf("Private Key: %s\n", to_hex_str(priv_key.data, sizeof(priv_key), temp_str, FALSE));
	mem_set(temp_str, 0, 1024);

	Ed25519Key pub_key = {0};
	if ((err = generate_pub_key(pub_key, priv_key))) {
		ERROR_LOG("Failed to generate the public key.", kocket_status_str[-err]);
		return err;
	}
	
	printf("Public Key: %s\n", to_hex_str(pub_key.data, sizeof(pub_key), temp_str, FALSE));
	mem_set(temp_str, 0, 1024);

	Ed25519Signature signature = {0};
	if ((err = sign(signature, priv_key, pub_key, data, len))) {
		ERROR_LOG("Failed to sign.", kocket_status_str[-err]);
		return err;
	}

	printf("Signature: %s\n", to_hex_str(signature, sizeof(signature), temp_str, FALSE));
	mem_set(temp_str, 0, 1024);
	
	if (verify_signature(pub_key, signature, data, len)) {
		printf("Failed to verify the signature.\n");
		return -KOCKET_INVALID_SIGNATURE;
	}
	
	return KOCKET_NO_ERROR;
}

#endif //_ED25519_H_

