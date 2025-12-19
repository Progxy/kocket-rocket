#ifndef _POLY1305_H_
#define _POLY1305_H_

#define _KOCKET_SPECIAL_TYPE_SUPPORT_
#define _KOCKET_UTILS_IMPLEMENTATION_
#define _KOCKET_PRINTING_UTILS_
#define _KOCKET_NO_PERROR_SUPPORT_
#include "../kocket_utils.h"
#include "./chacha20.h"
#include "../deps/chonky_nums.h"

/* Reference [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) */

#define POLY1305_PAD16(val) ((val) % 16)

typedef u8 poly1305_otk_t[32];
typedef u8 poly1305_tag_t[16];

static void poly1305_clamp(poly1305_tag_t r) {
	r[3]  &= 15;
	r[7]  &= 15;
	r[11] &= 15;
	r[15] &= 15;
	r[4]  &= 252;
	r[8]  &= 252;
	r[12] &= 252;
	return;
}

static const u8 poly1305_p[] = {
	0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static int poly1305_mac(const u8* msg, const u64 msg_len, const poly1305_otk_t key, poly1305_tag_t tag) {
	poly1305_tag_t r_data = {0};
	mem_cpy(r_data, key, sizeof(poly1305_tag_t));
	poly1305_clamp(r_data);
	
	const BigNum r = POS_STATIC_BIG_NUM(r_data, sizeof(poly1305_tag_t));
	
	poly1305_tag_t s_data = {0};
	mem_cpy(s_data, key + sizeof(poly1305_tag_t), sizeof(poly1305_tag_t));
	const BigNum s = POS_STATIC_BIG_NUM(s_data, sizeof(poly1305_tag_t));
	
	u8 a_data[32] = {0};
	BigNum a = POS_STATIC_BIG_NUM(a_data, 32); 
	
	const BigNum p = POS_STATIC_BIG_NUM(poly1305_p, 24);
	u8 n_data[24] = {0};
	BigNum n = POS_STATIC_BIG_NUM(n_data, 24);

	for (u64 i = 0; i < __ceil(msg_len, 16); ++i) {
		mem_set(n.data, 0, n.size);
		
		const unsigned int n_size = MIN(msg_len - i * 16, sizeof(poly1305_tag_t));
		mem_cpy(n.data, msg + ((i - 1) * 16), n_size);
		(n.data)[n_size] = 0x01;
		
		__chonky_add(&a, &a, &n);
		
		u8 temp_data[64] = {0};
		BigNum temp = POS_STATIC_BIG_NUM(temp_data, 64);
		if (__chonky_mul_s(&temp, &r, &a) == NULL) return -KOCKET_FAILED_OPERATION;
		
		mem_set(a.data, 0, a.size);
		if (__chonky_mod_mersenne(&a, &temp, &p) == NULL) return -KOCKET_FAILED_OPERATION;
	}
	
	__chonky_add(&a, &a, &s);
	mem_cpy(tag, a.data, sizeof(poly1305_tag_t));
	
	return KOCKET_NO_ERROR;
}

static void poly1305_key_gen(const cct_key_t key, const cct_nonce_t nonce, poly1305_otk_t otk) {
	cct_rand_t block_res = {0};
	u32 counter = 0;
	chacha20_block(key, counter, nonce, block_res);
	mem_cpy(otk, block_res, sizeof(poly1305_otk_t));
	return;
}

// NOTE: ciphertext size must be equal to plaintext_size + sizeof(poly1305_tag_t) (= plaintext_size + 16)
int chacha20_aead_encrypt(u8* ciphertext, const u8* aad, const u64 aad_size, const cct_key_t key, const cct_nonce_t iv, const u8* plaintext, const u64 plaintext_size) {
	poly1305_otk_t otk = {0};
	poly1305_key_gen(key, iv, otk);
	chacha20_encrypt(ciphertext, key, 1, iv, plaintext, plaintext_size);

	u8 pad_data[16] = {0};

	const u64 aad_size_bytes = bytes_len((u8*) &aad_size, 8);
	const u64 plaintext_size_bytes = bytes_len((u8*) &plaintext_size, 8);
	
	u64 mac_data_size = 0;
	u8* mac_data = concat(
		16, &mac_data_size, 
		aad, aad_size, 
		pad_data, POLY1305_PAD16(aad_size), 
		ciphertext, plaintext_size, 
		pad_data, POLY1305_PAD16(plaintext_size),
		(u8*) &aad_size, aad_size_bytes, 
		pad_data, POLY1305_PAD16(aad_size_bytes),
		(u8*) &plaintext_size, plaintext_size_bytes, 
		pad_data, POLY1305_PAD16(plaintext_size_bytes)
	);

	if (mac_data == NULL) {
		WARNING_LOG("Failed to concat the mac_data.");
		return -KOCKET_IO_ERROR;
	}
	
	int err = 0;
	poly1305_tag_t tag = {0};
	if ((err = poly1305_mac(mac_data, mac_data_size, otk, tag))) {
		KOCKET_SAFE_FREE(mac_data);
		return err;
	}
	
	KOCKET_SAFE_FREE(mac_data);

	mem_cpy(ciphertext + plaintext_size, tag, sizeof(poly1305_tag_t));
	
	return KOCKET_NO_ERROR;
}

int test_poly1305(u8* data, u64 size) {
	TODO("implement me.");
	return -KOCKET_TODO;
}

#endif //_POLY1305_H_

