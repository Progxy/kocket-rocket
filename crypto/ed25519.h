#ifndef _ED25519_H_
#define _ED25519_H_

#define _KOCKET_SPECIAL_TYPE_SUPPORT_
#define _KOCKET_UTILS_IMPLEMENTATION_
#define _KOCKET_PRINTING_UTILS_
#include "../kocket_utils.h"
#include "./chacha20.h"
#include "./sha512.h"

/* Reference: [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) */

// TODO: Refactor/Clean the code...

typedef u8  Ed25519Key[32];
typedef u8  Ed25519Signature[64];
typedef u8* Ed25519Coord;

Ed25519Coord encode_y(Ed25519Key key) {
	Ed25519Coord y = kocket_calloc(1, sizeof(Ed25519Key)); 
	if (y == NULL) {
		printf("Failed to allocate y-coordinate.\n");
		return NULL;
	}

	return y;
}

Ed25519Coord encode_x(Ed25519Key key) {
	Ed25519Coord x = kocket_calloc(1, sizeof(Ed25519Key)); 
	if (x == NULL) {
		printf("Failed to allocate x-coordinate.\n");
		return NULL;
	}

	return x;
}

Ed25519Coord decode_point(Ed25519Key key) {
	TODO("Implement me!");
	return NULL;
}

int generate_pub_key(Ed25519Key pub_key, Ed25519Key priv_key) {
	if (pub_key == NULL || priv_key == NULL) return -KOCKET_INVALID_PARAMETERS;

	int err = 0;
	u8 h[64] = {0};

	if ((err = sha512(priv_key, sizeof(Ed25519Key), (u64*) h))) return err;

	// Prune the buffer
	h[0] &= ~(0x07);
	h[31] &= ~(0x80);
	h[31] |= 0x40;

	mem_cpy(pub_key, h, sizeof(Ed25519Key));

	Ed25519Key sb = pub_key * priv_key;

	Ed25519Coord y_encoding = encode_y(sb);
	if (y_encoding == NULL) return -KOCKET_IO_ERROR;
	
	y_encoding[31] &= ~(0x80);
	
	Ed25519Coord x_encoding = encode_x(sb);
	if (x_encoding == NULL) return -KOCKET_IO_ERROR;
	
	mem_cpy(pub_key, y_encoding, sizeof(Ed25519Key));
	pub_key[31] &= ~((x_encoding[0] & 0x01) << 7);
	
	KOCKET_SAFE_FREE(x_encoding);
	KOCKET_SAFE_FREE(y_encoding);

	return KOCKET_NO_ERROR;
}

int generate_priv_key(Ed25519Key priv_key) {
	if (priv_key == NULL) return -KOCKET_INVALID_PARAMETERS;
	
	u8 random_data[64] = {0};
	cha_cha20(random_data);
	mem_cpy(priv_key, random_data, sizeof(Ed25519Key));
	
	return KOCKET_NO_ERROR;
}

int sign(Ed25519Signature signature, Ed25519Key priv_key, Ed25519Key pub_key, u8* data, u64 len) {
	if (data == NULL || len == 0 || pub_key == NULL || priv_key == NULL || signature == NULL) return -KOCKET_INVALID_PARAMETERS;
	int err = 0;

	u8 h[64] = {0};
	if ((err = sha512(priv_key, sizeof(Ed25519Key), (u64*) h))) return err;

	u8 hashed_data[64] = {0};
	// TODO: concatenate the prefix
	if ((err = sha512(data, len, (u64*) hashed_data))) return err;
	
	// TODO: For efficiency, do this by first reducing r modulo L, the group order of B.
	Ed25519Coord R = hashed_data * priv_key;

	u64 K_len = 0;
	// TODO: Find a way to macro function calculate the count of parameters
	u8* K = concat(6, &K_len, R, sizeof(R), pub_key, sizeof(Ed25519Key), data, len);
	if (K == NULL) return -KOCKET_IO_ERROR;
	
	u8 k[64] = {0};
	if ((err = sha512(K, K_len, (u64*) k))) return err;

	// TODO: L: order of edwards25519 in [RFC7748]
	// TODO: For efficiency, again reduce k modulo L first.
	Ed25519Key S = (hashed_data + k * s) % L;

	mem_cpy(signature, S, sizeof(Ed25519Key));
	mem_cpy(signature + sizeof(Ed25519Key), R, sizeof(Ed25519Key));

	return KOCKET_NO_ERROR;
}

int verify_signature(Ed25519Key pub_key, Ed25519Signature signature, u8* data, u64 len) {
	if (data == NULL || len == 0 || pub_key == NULL || signature == NULL) return -KOCKET_INVALID_PARAMETERS;
	Ed25519Key R = {0};
	Ed25519Key S = {0};

	mem_cpy(S, signature, sizeof(Ed25519Key));
	mem_cpy(R, signature + sizeof(Ed25519Key), sizeof(Ed25519Key));
	
	// TODO: Check the range 0 <= s < L
	
	Ed25519Coord decoded_r = decode_point(R);
	if (decoded_r == NULL) return -KOCKET_INVALID_POINT;

	Ed25519Coord decoded_A = decode_point(pub_key);
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
	if ((err = generate_priv_key(priv_key))) {
		ERROR_LOG("Failed to generate the private key.", kocket_status_str[-err]);
		return err;
	}
	
	printf("Private Key: %s\n", to_hex_str(priv_key, sizeof(priv_key), temp_str, FALSE));
	mem_set(temp_str, 0, 1024);

	Ed25519Key pub_key = {0};
	if ((err = generate_pub_key(pub_key, priv_key))) {
		ERROR_LOG("Failed to generate the public key.", kocket_status_str[-err]);
		return err;
	}
	
	printf("Public Key: %s\n", to_hex_str(pub_key, sizeof(pub_key), temp_str, FALSE));
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

