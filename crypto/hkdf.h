#ifndef _HKDF_H_

#define _KOCKET_SPECIAL_TYPE_SUPPORT_
#define _KOCKET_UTILS_IMPLEMENTATION_
#define _KOCKET_PRINTING_UTILS_
#define _KOCKET_NO_PERROR_SUPPORT_
#include "../kocket_utils.h"
#include "sha512.h"

#define EMPTY_BYTE_STRING { .data = NULL, .len = 0 }
#define SLICE_BYTE_STRING(byte_string, start, end) { .data = (byte_string).data + (start), .len = (end) - (start) }
#define FREE_BYTE_STRING(byte_string) KOCKET_SAFE_FREE((byte_string).data)

typedef struct ByteString {
	u8* data;
	u64 len;	
} ByteString;

#define DIGEST_SIZE 64
#define SHA_BLOCK_SIZE 128

#define PRINT_BYTE_STRING(byte_string) print_byte_string(#byte_string, byte_string)
void print_byte_string(const char* name, const ByteString byte_string) {
	printf("%s (len: %llu): ", name, byte_string.len);
	for (s64 i = byte_string.len - 1; i >= 0; --i) printf("%02X", (byte_string.data)[i]);
	printf("\n");
	return;
}

static int copy_byte_string(ByteString* dest, const ByteString src) {
	dest -> data = calloc(src.len, sizeof(u8));
	if (dest -> data == NULL) {
		WARNING_LOG("Failed to allocate byte string.");
		return -KOCKET_IO_ERROR;
	}
	
	mem_cpy(dest -> data, src.data, src.len);
	dest -> len = src.len;

	return KOCKET_NO_ERROR;
}

static int hmac_sha512(sha512_64_t digest, const ByteString text, const ByteString key) {	
	int err = 0;
	ByteString key_c = {0};
	
	if ((err = copy_byte_string(&key_c, key))) return err;

	// Inner padding
	unsigned char k_ipad[SHA_BLOCK_SIZE] = {0};    
	
	// Outer padding
	unsigned char k_opad[SHA_BLOCK_SIZE] = {0};
	
	// If key is longer than 64 bytes reset it to key = sha512(key)
	if (key_c.len > SHA_BLOCK_SIZE) {
		sha512_64_t tk = {0};
		if ((err = sha512(key_c.data, key_c.len, tk))) {
			FREE_BYTE_STRING(key_c);
			return err;
		}

		mem_cpy(key_c.data, tk, sizeof(sha512_64_t));
		key_c.len = DIGEST_SIZE;
	}

	PRINT_BYTE_STRING(key_c);

	/* start out by storing key in pads */
	mem_cpy(k_ipad, key_c.data, key_c.len);
	mem_cpy(k_opad, key_c.data, key_c.len);

	FREE_BYTE_STRING(key_c);

	/* XOR key with ipad and opad values */
	for (unsigned int i = 0; i < SHA_BLOCK_SIZE; ++i) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5C;
	}
	
	sha512_ctx context = {0};
    
	// Perform inner MD5
	// Init context for 1st pass
	sha512_init(&context); 
	
	// Start with inner pad 
	sha512_update(&context, k_ipad, SHA_BLOCK_SIZE);
	
	// Then text of datagram 
	sha512_update(&context, text.data, text.len); 
	
	// Finish up 1st pass 
	sha512_final(digest, &context);          
	
	// Perform outer MD5
	// Init context for 2nd pass 
	sha512_init(&context);                   
	
	// Start with outer pad 
	sha512_update(&context, k_opad, SHA_BLOCK_SIZE);     

	// Then results of 1st hash 
	sha512_update(&context, (u8*) digest, DIGEST_SIZE);     
	
	// Finish up 2nd pass 
	sha512_final(digest, &context);          

	return KOCKET_NO_ERROR;
}

static int hkdf_sha512_extract(sha512_64_t prk, const ByteString salt, const ByteString ikm) {
    u8 t_salt_data[DIGEST_SIZE] = {0};
	ByteString t_salt = { .data = t_salt_data, .len = DIGEST_SIZE };
	if (salt.data != NULL) mem_cpy(t_salt.data, salt.data, salt.len);

	PRINT_BYTE_STRING(t_salt);
	PRINT_BYTE_STRING(ikm);

	int err = 0;
	if ((err = hmac_sha512(prk, t_salt, ikm))) return err;

	PRINT_HASH((u8*) prk);

	return KOCKET_NO_ERROR;
}

static u64 bytes_len(const u8* val, const u64 len) {
	u64 bytes_len = len;
	for (s64 i = len - 1; i >= 0 && val[i]; --i, --bytes_len);
	return bytes_len;
}

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

static int hkdf_sha512_expand(u8* result, const sha512_64_t prk, const ByteString info, const u64 length) {
    if (length > (255 * DIGEST_SIZE)) {
        WARNING_LOG("Requested key length too long");
		return -KOCKET_INVALID_LENGTH;
	}

    ByteString okm = {0};
	
	sha512_64_t t = {0};
	u64 t_size = 0;
    u64 counter = 1;
	int err = 0;

	const ByteString prk_str = { .data = (u8*) prk, .len = DIGEST_SIZE };

    while (okm.len < length) {
		ByteString concatenation = {0};
		concatenation.data = concat(3, &(concatenation.len), t, t_size, info, info.len, (u8*) counter, bytes_len((u8*) &counter, 8));
        if (concatenation.data == NULL) {
			FREE_BYTE_STRING(okm);
			WARNING_LOG("Failed to allocate concatenation buffer.");
			return -KOCKET_IO_ERROR;
		}
		
		if ((err = hmac_sha512(t, prk_str, concatenation))) {
			FREE_BYTE_STRING(okm);
			FREE_BYTE_STRING(concatenation);
			return err;
		}
		
		FREE_BYTE_STRING(concatenation);

		extend_string(&(okm.data), &(okm.len), (u8*) t, t_size);
        if (okm.data == NULL) {
			WARNING_LOG("Failed to extend okm buffer.");
			return -KOCKET_IO_ERROR;
		}

		counter += 1;
		t_size = DIGEST_SIZE;
	}
	
	mem_cpy(result, okm.data, length);
	FREE_BYTE_STRING(okm);

	return KOCKET_NO_ERROR;
}

static int hkdf_sha512(u8* result, const ByteString ikm, const u64 length, const ByteString salt, const ByteString info) {
	int err = 0;
	sha512_64_t prk = {0};
	if ((err = hkdf_sha512_extract(prk, salt, ikm))) return err;
    
	if ((err = hkdf_sha512_expand(result, prk, info, length))) return err;
	
	return KOCKET_NO_ERROR;
}

int test_hkdf(void) {
	u8 key_material_data[44] = {0};
    ByteString key_material = { .data = key_material_data, .len = 44 };
	ByteString salt = EMPTY_BYTE_STRING;

	const u8 RECIPIENT_PUB[32] = {
		0x66, 0xCA, 0xE6, 0x13, 0x6E, 0x7A, 0xE8, 0x2F,
		0x67, 0x71, 0x5A, 0x37, 0x16, 0x2E, 0x14, 0xC2, 
		0xCF, 0x51, 0x5C, 0x0A, 0x95, 0x13, 0x56, 0x40, 
		0xE9, 0x32, 0x0C, 0xB4, 0x12, 0x08, 0xC7, 0x3D
	};

	const u8 SENDER_PUB[32] = {
		0x26, 0x20, 0xFC, 0x1D, 0xAA, 0x0D, 0x73, 0xC2, 
		0xB0, 0x09, 0xF8, 0xCD, 0x99, 0xAA, 0xC8, 0x7F, 
		0xC5, 0xA1, 0x50, 0xD8, 0x6D, 0xC7, 0xFA, 0xB5, 
		0xAA, 0x39, 0xFB, 0x8B, 0x6F, 0x39, 0x89, 0x88
	};

	const char* info_str = "X25519-CHACHA20POLY1305-v1";
	u64 sequence_number = 1;
	
	u64 info_size = 0;
	u8* info_data = concat(4, &info_size, info_str, sizeof(info_str), SENDER_PUB, 32, RECIPIENT_PUB, 32, (u8*) sequence_number, 8);
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

	const ByteString shared_secret = { .data = (u8*) SHARED, .len = 32 };

	int err = 0;
	if ((err = hkdf_sha512(key_material.data, shared_secret, 44, salt, info))) {
		KOCKET_SAFE_FREE(info.data);
		return err;
	}
	
	FREE_BYTE_STRING(info);

    ByteString aead_key = SLICE_BYTE_STRING(key_material, 0, 32);
    ByteString aead_nonce = SLICE_BYTE_STRING(key_material, 32, 44);

    PRINT_BYTE_STRING(aead_key);
	PRINT_BYTE_STRING(aead_nonce);
	
	return KOCKET_NO_ERROR;
}

#endif //_HKDF_H_
