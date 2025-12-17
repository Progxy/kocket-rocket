#ifndef _HMAC_H_
#define _HMAC_H_

#define _KOCKET_SPECIAL_TYPE_SUPPORT_
#define _KOCKET_UTILS_IMPLEMENTATION_
#define _KOCKET_PRINTING_UTILS_
#define _KOCKET_NO_PERROR_SUPPORT_
#include "../kocket_utils.h"
#include "common_sha.h"

#define EMPTY_BYTE_STRING { .data = NULL, .len = 0 }
#define SLICE_BYTE_STRING(byte_string, start, end) { .data = (byte_string).data + (start), .len = (end) - (start) }
#define FREE_BYTE_STRING(byte_string) KOCKET_SAFE_FREE((byte_string).data)

typedef struct ByteString {
	u8* data;
	u64 len;	
} ByteString;

#define PRINT_BYTE_STRING(byte_string) print_byte_string(#byte_string, byte_string, FALSE)
#define PRINT_BYTE_STRING_BE(byte_string) print_byte_string(#byte_string, byte_string, TRUE)
void print_byte_string(const char* name, const ByteString byte_string, const bool use_be) {
	printf("%s (len: %llu): ", name, byte_string.len);
	if (use_be) {
		for (u64 i = 0; i < byte_string.len; ++i) printf("%02X", (byte_string.data)[i]);
	} else {
		for (s64 i = byte_string.len - 1; i >= 0; --i) printf("%02X", (byte_string.data)[i]);
	}
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

// NOTE: key and text will be considered Big-Endian
static int hmac_sha(sha_t* digest, const ByteString key, const ByteString text, const sha_fn sha_fn) {	
	int err = 0;
	ByteString key_c = {0};
	
	if ((err = copy_byte_string(&key_c, key))) return err;

	// Inner padding
	u8 k_ipad_data[MAX_SHA_BLOCK_SIZE] = {0};    
	ByteString k_ipad = { .data = k_ipad_data, .len = sha_fn.block_size };

	u8 k_opad_data[MAX_SHA_BLOCK_SIZE] = {0};    
	ByteString k_opad = { .data = k_opad_data, .len = sha_fn.block_size };
	
	// If key is longer than 64 bytes reset it to key = sha512(key)
	if (key_c.len > sha_fn.block_size) {
		sha_t tk = {0};
		sha_fn.sha(key_c.data, key_c.len, &tk);
		mem_cpy(key_c.data, tk.ptr, sha_fn.digest_size);
		key_c.len = sha_fn.digest_size;
	}

	mem_cpy(k_ipad.data, key_c.data, key_c.len);
	mem_cpy(k_opad.data, key_c.data, key_c.len);

	FREE_BYTE_STRING(key_c);

	for (unsigned int i = 0; i < sha_fn.block_size; ++i) {
		k_ipad.data[i] ^= 0x36;
		k_opad.data[i] ^= 0x5C;
	}
	
	sha_ctx context = {0};
	sha_fn.sha_init(&context);
	sha_fn.sha_update(&context, k_ipad.data, k_ipad.len);
	sha_fn.sha_update(&context, text.data, text.len); 
	sha_fn.sha_final(digest, &context);          
	
	sha_fn.sha_init(&context);                   
	sha_fn.sha_update(&context, k_opad.data, k_opad.len);     
	sha_fn.sha_update(&context, digest -> ptr, sha_fn.digest_size);     
	sha_fn.sha_final(digest, &context);          
	
	return KOCKET_NO_ERROR;
}


#endif //_HMAC_H_

