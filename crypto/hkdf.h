#ifndef _HKDF_H_

#define _KOCKET_SPECIAL_TYPE_SUPPORT_
#define _KOCKET_UTILS_IMPLEMENTATION_
#define _KOCKET_PRINTING_UTILS_
#define _KOCKET_NO_PERROR_SUPPORT_
#include "../kocket_utils.h"
#include "hmac.h"

static void extend_string(u8** str, u64* size, const u8* str_to_add, const u64 size_str_to_add) {
	*str = kocket_realloc(*str, *size + size_str_to_add);
	if (*str == NULL) {
		WARNING_LOG("Failed to reallocate buffer for str");
		return;
	}

	mem_cpy(*str + *size, str_to_add, size_str_to_add);
	*size += size_str_to_add;

	return;
}

static int hkdf_sha_extract(sha_t* prk, const ByteString salt, const ByteString ikm, const sha_fn sha_fn) {
    u8 t_salt_data[MAX_SHA_BLOCK_SIZE] = {0};
	ByteString t_salt = { .data = t_salt_data, .len = sha_fn.digest_size };
	if (salt.data != NULL) {
		mem_cpy(t_salt.data, salt.data, salt.len);
		KOCKET_BE_CONVERT(t_salt.data, t_salt.len);
	}

	KOCKET_BE_CONVERT(ikm.data, ikm.len);
	
	int err = 0;
	if ((err = hmac_sha(prk, t_salt, ikm, sha_fn))) return err;

	KOCKET_BE_CONVERT(ikm.data, ikm.len);

	return KOCKET_NO_ERROR;
}

static int hkdf_sha_expand(u8* result, const sha_t* prk, const ByteString info, const u64 length, const sha_fn sha_fn) {
    if (length > (255 * sha_fn.digest_size)) {
        WARNING_LOG("Requested key length too long");
		return -KOCKET_INVALID_LENGTH;
	}

    ByteString okm = {0};
	
	sha_t t = {0};
	u64 t_size = 0;
    u64 counter = 1;
	int err = 0;

	const ByteString prk_str = { .data = (u8*) prk -> ptr, .len = sha_fn.digest_size };
	KOCKET_BE_CONVERT(info.data, info.len);

    while (okm.len < length) {
		u64 counter_len = bytes_len((u8*) &counter, 8);

		ByteString concatenation = {0};
		concatenation.data = concat(6, &(concatenation.len), t.ptr, t_size, info.data, info.len, &counter, counter_len);
        if (concatenation.data == NULL) {
			FREE_BYTE_STRING(okm);
			WARNING_LOG("Failed to allocate concatenation buffer.");
			return -KOCKET_IO_ERROR;
		}
		
		if ((err = hmac_sha(&t, prk_str, concatenation, sha_fn))) {
			FREE_BYTE_STRING(okm);
			FREE_BYTE_STRING(concatenation);
			return err;
		}
		
		t_size = sha_fn.digest_size;
		
		FREE_BYTE_STRING(concatenation);

		extend_string(&(okm.data), &(okm.len), t.ptr, t_size);
        if (okm.data == NULL) {
			WARNING_LOG("Failed to extend okm buffer.");
			return -KOCKET_IO_ERROR;
		}
		
		counter += 1;
	}
	
	mem_cpy(result, okm.data, length);
	FREE_BYTE_STRING(okm);
	
	KOCKET_BE_CONVERT(result, length);

	return KOCKET_NO_ERROR;
}

static int hkdf_sha(u8* result, const ByteString ikm, const u64 length, const ByteString salt, const ByteString info, const sha_fn sha_fn) {
	int err = 0;
	sha_t prk = {0};
	if ((err = hkdf_sha_extract(&prk, salt, ikm, sha_fn))) return err;
	if ((err = hkdf_sha_expand(result, &prk, info, length, sha_fn))) return err;
	return KOCKET_NO_ERROR;
}

int test_hkdf(void) {
	u8 key_material_data[44] = {0};
    ByteString key_material = { .data = key_material_data, .len = 44 };
	ByteString salt = EMPTY_BYTE_STRING;

	u8 RECIPIENT_PUB[32] = {
		0x66, 0xCA, 0xE6, 0x13, 0x6E, 0x7A, 0xE8, 0x2F,
		0x67, 0x71, 0x5A, 0x37, 0x16, 0x2E, 0x14, 0xC2, 
		0xCF, 0x51, 0x5C, 0x0A, 0x95, 0x13, 0x56, 0x40, 
		0xE9, 0x32, 0x0C, 0xB4, 0x12, 0x08, 0xC7, 0x3D
	};

	u8 SENDER_PUB[32] = {
		0x26, 0x20, 0xFC, 0x1D, 0xAA, 0x0D, 0x73, 0xC2, 
		0xB0, 0x09, 0xF8, 0xCD, 0x99, 0xAA, 0xC8, 0x7F, 
		0xC5, 0xA1, 0x50, 0xD8, 0x6D, 0xC7, 0xFA, 0xB5, 
		0xAA, 0x39, 0xFB, 0x8B, 0x6F, 0x39, 0x89, 0x88
	};

	KOCKET_BE_CONVERT(RECIPIENT_PUB, 32);
	KOCKET_BE_CONVERT(SENDER_PUB, 32);

	char info_str[] = "X25519-CHACHA20POLY1305-v1";
	u64 sequence_number = 1;

	u64 info_size = 0;
	u8* info_data = concat(8, &info_size, info_str, sizeof(info_str) - 1, SENDER_PUB, 32, RECIPIENT_PUB, 32, (u8*) &sequence_number, 8);
    if (info_data == NULL) {
		WARNING_LOG("Failed to concatenate info buffer.");
		return -KOCKET_IO_ERROR;
	}
	
	ByteString info = { .data = info_data, .len = info_size };
	const u8 SHARED[32] = {
		0x42, 0x85, 0x18, 0x38, 0x56, 0xD1, 0x11, 0xB4, 
		0xB1, 0x60, 0x7D, 0x13, 0xE7, 0xAF, 0x5D, 0xAD, 
		0x26, 0x63, 0x13, 0x09, 0x8A, 0xF5, 0x75, 0x88, 
		0x3C, 0x30, 0x87, 0x71, 0xC8, 0xF7, 0xB1, 0x70
	};
	
	KOCKET_BE_CONVERT(info.data, info.len);

	const ByteString shared_secret = { .data = (u8*) SHARED, .len = 32 };

	int err = 0;
	if ((err = hkdf_sha(key_material.data, shared_secret, 44, salt, info, sha512_fn))) {
		KOCKET_SAFE_FREE(info.data);
		return err;
	}
	
	FREE_BYTE_STRING(info);
	
	PRINT_BYTE_STRING(key_material);
	
    ByteString aead_key = SLICE_BYTE_STRING(key_material, 12, 44);
    ByteString aead_nonce = SLICE_BYTE_STRING(key_material, 0, 12);

	const u8 aead_key_data[] = {
		0xE8, 0x19, 0x28, 0xB9, 0x90, 0xF3, 0x69, 0xCF,
	   	0xE8, 0x57, 0xFB, 0x61, 0x0B, 0xC1, 0xE6, 0x3E, 
		0xBA, 0xDC, 0xBD, 0x4A, 0xAF, 0x0A, 0x40, 0x72, 
		0x83, 0x9C, 0x48, 0x03, 0x4E, 0xD8, 0x21, 0x09
	};

	const u8 aead_nonce_data[] = {
		0x90, 0xB2, 0x7D, 0xB3, 0x12, 0xE6, 
		0x30, 0xF0, 0xB1, 0xD4, 0xA8, 0x49
	};

    PRINT_BYTE_STRING(aead_key);
	PRINT_BYTE_STRING(aead_nonce);

	if (mem_cmp(aead_key.data, aead_key_data, sizeof(aead_key_data))) {
		WARNING_LOG("mismatch aead_key");
		return 1;
	}

	if (mem_cmp(aead_nonce.data, aead_nonce_data, sizeof(aead_nonce_data))) {
		WARNING_LOG("mismatch aead_key");
		return 1;
	}
	
	return KOCKET_NO_ERROR;
}

#endif //_HKDF_H_
