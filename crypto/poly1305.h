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

typedef u8 poly1305_otk_t[32];
typedef u8 poly1305_tag_t[16];

static inline u64 poly1305_pad16(const u64 val) {
	if ((val % 16) == 0) return 0;
	return 16 - (val % 16);
}

static void poly1305_clamp(poly1305_tag_t r) {
	r[12] &= 15;
	r[8]  &= 15;
	r[4]  &= 15;
	r[0]  &= 15;
	r[11] &= 252;
	r[7]  &= 252;
	r[3]  &= 252;
	return;
}

static const u8 poly1305_p[] = {
	0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define PRINT_POLY1305_TAG(tag) print_poly1305_tag(tag, #tag)
static void print_poly1305_tag(const poly1305_tag_t tag, const char* name) {
	printf("%s: ", name);
	for (int i = 15; i >= 0; --i) printf("%02X", tag[i]);
	printf("\n");
	return;
}

#define PRINT_POLY1305_OTK(otk) print_poly1305_otk(otk, #otk)
static void print_poly1305_otk(const poly1305_otk_t otk, const char* name) {
	printf("%s: ", name);
	for (int i = 31; i >= 0; --i) printf("%02X", otk[i]);
	printf("\n");
	return;
}

/// NOTE: msg must be in big endian format
static int poly1305_mac(const u8* msg, const u64 msg_len, const poly1305_otk_t key, poly1305_tag_t tag) {
	poly1305_tag_t r_data = {0};
	mem_cpy(r_data, key + sizeof(poly1305_tag_t), sizeof(poly1305_tag_t));
	for (unsigned int i = 0; i < 4; ++i) KOCKET_BE_CONVERT(((u32*) r_data) + i, sizeof(u32));
	poly1305_clamp(r_data);
	KOCKET_BE_CONVERT(r_data, sizeof(poly1305_tag_t));

	const BigNum r = POS_STATIC_BIG_NUM(r_data, sizeof(poly1305_tag_t));

	poly1305_tag_t s_data = {0};
	mem_cpy(s_data, key, sizeof(poly1305_tag_t));
	for (unsigned int i = 0; i < 4; ++i) KOCKET_BE_CONVERT(((u32*) s_data) + i, sizeof(u32));
	KOCKET_BE_CONVERT(s_data, sizeof(poly1305_tag_t));
	
	const BigNum s = POS_STATIC_BIG_NUM(s_data, sizeof(poly1305_tag_t));
	
	u8 a_data[32] = {0};
	BigNum a = POS_STATIC_BIG_NUM(a_data, 32); 
	
	const BigNum p = POS_STATIC_BIG_NUM(poly1305_p, 24);
	u8 n_data[24] = {0};
	BigNum n = POS_STATIC_BIG_NUM(n_data, 24);

	for (u64 i = 0; i < __ceil(msg_len, 16); ++i) {
		mem_set(n.data, 0, n.size);

		const unsigned int n_size = MIN(msg_len - i * 16, sizeof(poly1305_tag_t));
		mem_cpy(n.data, msg + (i * 16), n_size);
		(n.data)[n_size] = 0x01;

		u8 tmp_data[32] = {0};
		BigNum tmp = POS_STATIC_BIG_NUM(tmp_data, 32);
		__chonky_add(&tmp, &a, &n);
		
		u8 temp_data[64] = {0};
		BigNum temp = POS_STATIC_BIG_NUM(temp_data, 64);
		if (__chonky_mul_s(&temp, &r, &tmp) == NULL) return -KOCKET_FAILED_OPERATION;
		
		mem_set(a.data, 0, a.size);
		if (__chonky_mod_mersenne(&a, &temp, &p) == NULL) return -KOCKET_FAILED_OPERATION;
	}
	
	u8 tmp_data[32] = {0};
	BigNum tmp = POS_STATIC_BIG_NUM(tmp_data, 32);
	__chonky_add(&tmp, &a, &s);
	
	mem_cpy(tag, tmp.data, sizeof(poly1305_tag_t));
	KOCKET_BE_CONVERT(tag, sizeof(poly1305_tag_t));

	return KOCKET_NO_ERROR;
}

static void poly1305_key_gen(const cct_key_t key, const cct_nonce_t nonce, poly1305_otk_t otk) {
	cct_rand_t block_res = {0};
	u32 counter = 0;
	chacha20_block(key, counter, nonce, block_res);
	mem_cpy(otk, block_res + sizeof(poly1305_otk_t), sizeof(poly1305_otk_t));
	return;
}

int aead_chacha20_poly1305_encrypt(u8* ciphertext, poly1305_tag_t tag, const u8* aad, const u64 aad_size, const cct_key_t key, const cct_nonce_t iv, const u8* plaintext, const u64 plaintext_size) {
	poly1305_otk_t otk = {0};
	poly1305_key_gen(key, iv, otk);

	chacha20_encrypt(ciphertext, key, 1, iv, plaintext, plaintext_size);

	u8 pad_data[16] = {0};

	const u64 aad_size_bytes = bytes_len((u8*) &aad_size, 8);
	const u64 plaintext_size_bytes = bytes_len((u8*) &plaintext_size, 8);
	
	u64 mac_data_size = 0;
	u8* mac_data = concat(
		16, &mac_data_size, 
		pad_data, 8 - plaintext_size_bytes,
		(u8*) &plaintext_size, plaintext_size_bytes, 
		pad_data, 8 - aad_size_bytes,
		(u8*) &aad_size, aad_size_bytes, 
		pad_data, poly1305_pad16(plaintext_size),
		ciphertext, plaintext_size, 
		pad_data, poly1305_pad16(aad_size),
		aad, aad_size 
	);

	if (mac_data == NULL) {
		WARNING_LOG("Failed to concat the mac_data.");
		return -KOCKET_IO_ERROR;
	}
		
	KOCKET_BE_CONVERT(mac_data, mac_data_size);

	for (unsigned int i = 0; i < 8; ++i) KOCKET_BE_CONVERT(((u32*) otk) + i, sizeof(u32));

	int err = 0;
	if ((err = poly1305_mac(mac_data, mac_data_size, otk, tag))) {
		KOCKET_SAFE_FREE(mac_data);
		return err;
	}
	
	KOCKET_SAFE_FREE(mac_data);
	
	return KOCKET_NO_ERROR;
}

int test_poly1305(u8* data, u64 size) {
	int ret = 0;
	const u8 msg[35] = "Cryptographic Forum Research Group";
	const u64 msg_len = KOCKET_ARR_SIZE(msg) - 1;

	const poly1305_otk_t key = {
		0x41, 0x49, 0xF5, 0x1B,
		0x4A, 0xBF, 0xF6, 0xAF,
		0xFB, 0x0D, 0xB2, 0xFD,
		0x01, 0x03, 0x80, 0x8A,
		0x42, 0xD5, 0x06, 0xA8,
		0x7F, 0x44, 0x52, 0xFE,
		0x57, 0x55, 0x6D, 0x33,
		0x85, 0xD6, 0xBE, 0x78
	};
	
	const poly1305_tag_t test_tag = {
		0xA9, 0x27, 0x01, 0x0C, 
		0xAF, 0x8B, 0x2B, 0xC2,
	   	0xC6, 0x36, 0x51, 0x30, 
		0xC1, 0x1D, 0x06, 0xA8
	};

	printf("Testing poly1305_mac: ");
	poly1305_tag_t tag = {0};
	if ((ret = poly1305_mac(msg, msg_len, key, tag))) {
		WARNING_LOG("Failed to run poly1305_mac");
		return ret;
	}
	
	if (mem_cmp(tag, test_tag, sizeof(poly1305_tag_t))) {
		PRINT_POLY1305_TAG(tag);
		PRINT_POLY1305_TAG(test_tag);
		WARNING_LOG("Failed testing poly1305_mac.");
		return 1;
	}

	printf("Test Passed!\n");

	const cct_nonce_t nonce = {
		0x04, 0x05, 0x06, 0x07,
		0x00, 0x01, 0x02, 0x03, 
		0x00, 0x00, 0x00, 0x00
	};
	
	const poly1305_otk_t key_ = {
		0x9C, 0x9D, 0x9E, 0x9F, 
		0x98, 0x99, 0x9A, 0x9B, 
		0x94, 0x95, 0x96, 0x97, 
		0x90, 0x91, 0x92, 0x93, 
		0x8C, 0x8D, 0x8E, 0x8F, 
		0x88, 0x89, 0x8A, 0x8B, 
		0x84, 0x85, 0x86, 0x87, 
		0x80, 0x81, 0x82, 0x83
	}; 
	
	const poly1305_otk_t test_otk = {
		0x46, 0xA6, 0xD1, 0xFD, 0xE2, 0xB8, 0xDB, 0x08, 
		0xA5, 0x0D, 0xFD, 0xE3, 0x37, 0xB6, 0x33, 0xA8, 
		0x71, 0x94, 0xB2, 0x4A, 0x27, 0x40, 0x50, 0x81, 
		0xCC, 0x81, 0x5F, 0x90, 0x8B, 0xA0, 0xD5, 0x8A
	};
	
	printf("Testing poly1305_key_gen: ");
	poly1305_otk_t otk = {0};
	poly1305_key_gen(key_, nonce, otk);
	
	if (mem_cmp(otk, test_otk, sizeof(poly1305_otk_t))) {
		PRINT_POLY1305_OTK(otk);
		PRINT_POLY1305_OTK(test_otk);
		WARNING_LOG("Failed testing poly1305_key_gen.");
		return 1;
	}

	printf("Test Passed!\n");

	const u8 plaintext[115] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
	const u64 plaintext_size = KOCKET_ARR_SIZE(plaintext) - 1;

	const u8 aad[] = {
		0xC7, 0xC6, 0xC5, 0xC4, 
		0xC3, 0xC2, 0xC1, 0xC0, 
		0x53, 0x52, 0x51, 0x50
	};
	const u64 aad_size = KOCKET_ARR_SIZE(aad);

	const cct_nonce_t iv = {
		0x44, 0x45, 0x46, 0x47,
		0x40, 0x41, 0x42, 0x43, 
		0x07, 0x00, 0x00, 0x00,
	}; 

	printf("Testing aead_chacha20_poly1305_encrypt: ");
	
	poly1305_tag_t tag_ = {0};
	u8 ciphertext[114] = {0};
	if ((ret = aead_chacha20_poly1305_encrypt(ciphertext, tag_, aad, aad_size, key_, iv, plaintext, plaintext_size))) {
		WARNING_LOG("Failed to run aead_chacha20_poly1305_encrypt");
		return ret;
	}
	
	const u8 test_ciphertext[] = {
		0x16, 0x61, 0x4B, 0xC6, 0xCE, 0x86, 0x65, 0xD2,
	   	0x76, 0xE5, 0x9D, 0x7A, 0x4B, 0x8E, 0xF0, 0xDE, 
		0xF4, 0x3F, 0xBC, 0xD7, 0x31, 0x48, 0x8B, 0x80, 
		0x85, 0x55, 0x94, 0x75, 0xD6, 0xFA, 0xE4, 0x24, 
		0xB3, 0xFA, 0x58, 0x1B, 0x09, 0x28, 0xE3, 0xAE, 
		0x03, 0x98, 0x8C, 0x8B, 0x77, 0x2D, 0x7F, 0xBD, 
		0xDD, 0x92, 0x36, 0x3B, 0xCD, 0x7E, 0xB6, 0xA5, 
		0xD6, 0x05, 0x29, 0x0B, 0x06, 0x9E, 0x0A, 0xDE, 
		0x71, 0x1A, 0x8B, 0x72, 0x92, 0xDA, 0x69, 0xFB, 
		0xFA, 0x82, 0x12, 0x67, 0xA9, 0x8C, 0x5E, 0xA4, 
		0xBE, 0x3D, 0xD6, 0x62, 0xEE, 0x36, 0xA7, 0xB5, 
		0xE2, 0xA9, 0xFE, 0x08, 0x6E, 0x29, 0x51, 0xED, 
		0xAD, 0xA4, 0xC2, 0x7E, 0xEF, 0x53, 0xBC, 0xAF, 
		0x86, 0x7B, 0xDB, 0x60, 0x8E, 0x64, 0x34, 0x8D, 
		0x1A, 0xD3
	};

	const poly1305_tag_t test_tag_ = {
		0x91, 0x06, 0x60, 0xD0, 
		0xCB, 0x2E, 0x90, 0x7E, 
		0x6A, 0xE2, 0x09, 0x4F, 
		0x59, 0x0B, 0xE1, 0x1A
	};

	if (mem_cmp(ciphertext, test_ciphertext, plaintext_size)) {
		PRINT_CCT_CIPHER(ciphertext, plaintext_size);
		PRINT_CCT_CIPHER(test_ciphertext, plaintext_size);
		WARNING_LOG("Failed testing aead_chacha20_poly1305_encrypt.");
		return 1;
	}

	if (mem_cmp(tag_, test_tag_, sizeof(poly1305_tag_t))) {
		PRINT_POLY1305_TAG(tag_);
		PRINT_POLY1305_TAG(test_tag_);
		WARNING_LOG("Failed testing aead_chacha20_poly1305_encrypt.");
		return 1;
	}

	printf("Test Passed!\n");
	
	return KOCKET_NO_ERROR;
}

#endif //_POLY1305_H_

