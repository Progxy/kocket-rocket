#ifndef _COMMON_SHA_H_
#define _COMMON_SHA_H_

#define _KOCKET_SPECIAL_TYPE_SUPPORT_
#define _KOCKET_UTILS_IMPLEMENTATION_
#define _KOCKET_PRINTING_UTILS_
#define _KOCKET_NO_PERROR_SUPPORT_
#include "../kocket_utils.h"

// ------------------
//  Macros Functions
// ------------------
#if __has_builtin(__builtin_stdc_rotate_right)
	#define ROTR __builtin_stdc_rotate_right
#elif __has_builtin(__builtin_rotateright64) 
	#define ROTR __builtin_rotateright64
#else
	#define ROTR(x, r) (((x) >> (r)) | ((x) << (64 - (r))))
#endif

#define CH(x, y, z)  (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// TODO: sha256 and sha512 could be merged, so that it would also be easier for
// implementing the two remaining hash algorithms
typedef enum ShaSizes {
	SHA512_BLOCK_SIZE          = 1024,
	SHA512_DIGEST_SIZE         = 64,
	SHA512_BLOCK_SIZE_IN_BYTES = 128,
	SHA256_BLOCK_SIZE          = 512,
	SHA256_DIGEST_SIZE         = 32,
	SHA256_BLOCK_SIZE_IN_BYTES = 64,
	MAX_SHA_BLOCK_SIZE         = SHA512_BLOCK_SIZE_IN_BYTES,
	MAX_SHA_DIGEST_SIZE        = SHA512_DIGEST_SIZE
} ShaSizes;

typedef u8 sha512_t[64];
typedef u64 sha512_64_t[8];
typedef u8 sha256_t[32];
typedef u32 sha256_32_t[8];

typedef union sha_t {
	sha512_t sha512_t;
	sha512_64_t sha512_64_t;
	sha256_t sha256_t;
	sha256_32_t sha256_32_t;
	u8 ptr[MAX_SHA_DIGEST_SIZE];
} sha_t;

typedef struct sha_ctx {
	sha_t hash;
	u8 msg_block[MAX_SHA_BLOCK_SIZE * 2];
	u64 msg_block_size;
	bool is_finished;
	u64 total_msg_size;
} sha_ctx;

typedef struct sha_fn {
	u64 digest_size;
	u64 block_size;
	void (*sha_init)     (sha_ctx* ctx);
	int  (*sha_update)   (sha_ctx* ctx, const u8* data, const u64 len);
	int  (*sha_final)    (sha_t* digest, sha_ctx* ctx);
	int  (*sha_final_le) (sha_t* digest, sha_ctx* ctx);
	void (*sha_le)       (const u8* data, const u64 len, sha_t* digest);
	void (*sha)          (const u8* data, const u64 len, sha_t* digest);
} sha_fn;

#define PRINT_HASH(hash) print_hash(#hash, hash)
static void print_hash(const char* name, const sha_t hash) {
	printf("%s:\n", name);

	bool is_still_zero = TRUE;
	u64 hash_size = 64;
	printf("\tLittle Endian: ");
	for (int i = MAX_SHA_DIGEST_SIZE - 1; i >= 0; --i) {
		if (is_still_zero && (hash.ptr[i] == 0)) {
			hash_size--;
			continue;
		}
		printf("%02X", hash.ptr[i]);
		is_still_zero = FALSE;
	}
	printf("\n");
	
	printf("\tBig Endian:    ");
	for (unsigned int i = 0; i < hash_size; ++i) printf("%02X", hash.ptr[i]);
	printf("\n");
	
	return;
}

#define PRINT_SHA_CTX(ctx) print_sha_ctx(#ctx, ctx)
UNUSED_FUNCTION static void print_sha_ctx(const char* name, const sha_ctx ctx) {
	printf("---- SHA-CTX %s: ------\n", name);
	
	PRINT_HASH(ctx.hash);
	
	printf("\tmsg_block_size: %llu\n", ctx.msg_block_size);
	
	printf("\tmsg_block (low msg block): ");
	for (int i = MAX_SHA_BLOCK_SIZE - 1; i >= 0; --i) printf("%02X", ctx.msg_block[i]);
	printf("\n");
	
	printf("\tmsg_block (high msg block): ");
	for (int i = MAX_SHA_BLOCK_SIZE * 2 - 1; i >= MAX_SHA_BLOCK_SIZE; --i) printf("%02X", ctx.msg_block[i]);
	printf("\n");
	
	printf("\ttotal_msg_size: %llu\n", ctx.total_msg_size);
	printf("\tis_finished: %s\n", ctx.is_finished ? "TRUE" : "FALSE");
	
	printf("----------------\n");

	return;
}

#include "sha512.h"
#include "sha256.h"

#endif //_COMMON_SHA_H_

