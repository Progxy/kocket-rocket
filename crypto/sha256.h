#ifndef _SHA256_H_
#define _SHA256_H_

/* Reference: [RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234) */

// TODO: Refactor/Clean the code...

// ------------------
//  Macros Functions
// ------------------
#define BSIG0_256(x) (ROTR((x), 2)  ^ ROTR((x), 13) ^ ROTR((x), 22))
#define BSIG1_256(x) (ROTR((x), 6)  ^ ROTR((x), 11) ^ ROTR((x), 25))
#define SSIG0_256(x) (ROTR((x), 7)  ^ ROTR((x), 18) ^ ((x) >> 3))
#define SSIG1_256(x) (ROTR((x), 17) ^ ROTR((x), 19) ^ ((x) >> 10))

// -----------------------
//  Function Declarations
// -----------------------
void sha256_init(sha_ctx* ctx);
int sha256_update(sha_ctx* ctx, const u8* data, const u64 len);
int sha256_final(sha_t* digest, sha_ctx* ctx);
int sha256_final_le(sha_t* digest, sha_ctx* ctx);
void sha256_le(const u8* data, const u64 len, sha_t* digest);
void sha256(const u8* data, const u64 len, sha_t* digest);

// ------------------
//  Static Variables
// ------------------
static const sha_fn sha256_fn = {
	.digest_size = SHA256_DIGEST_SIZE,
	.block_size = SHA256_BLOCK_SIZE_IN_BYTES,
	.sha_init = sha256_init,
	.sha_update = sha256_update,
	.sha_final = sha256_final,
	.sha_final_le = sha256_final_le,
	.sha_le = sha256_le,
	.sha = sha256
};

static const u32 costants_256[] = {
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

void sha256_init(sha_ctx* ctx) {
	mem_set(ctx -> hash.sha256_t, 0, sizeof(ctx -> hash.sha256_t));

	(ctx -> hash.sha256_32_t)[0] = 0x6A09E667;
    (ctx -> hash.sha256_32_t)[1] = 0xBB67AE85;
    (ctx -> hash.sha256_32_t)[2] = 0x3C6EF372;
    (ctx -> hash.sha256_32_t)[3] = 0xA54FF53A;
    (ctx -> hash.sha256_32_t)[4] = 0x510E527F;
    (ctx -> hash.sha256_32_t)[5] = 0x9B05688C;
    (ctx -> hash.sha256_32_t)[6] = 0x1F83D9AB;
    (ctx -> hash.sha256_32_t)[7] = 0x5BE0CD19;
	
	mem_set(ctx -> msg_block, 0, SHA256_BLOCK_SIZE_IN_BYTES * 2);
	ctx -> msg_block_size = 0;
	ctx -> total_msg_size = 0;
	ctx -> is_finished = FALSE;
	
	return;
}

static void process_block_256(sha_ctx* ctx) {
	u32 W[64] = {0};

	mem_cpy(W, ctx -> msg_block, SHA256_BLOCK_SIZE_IN_BYTES);
	for (unsigned int t = 0; t < 16; ++t) KOCKET_BE_CONVERT(W + t, 4);
	for (unsigned int t = 16; t < 64; ++t) {
		W[t] = SSIG1_256(W[t - 2]) + W[t - 7] + SSIG0_256(W[t - 15]) + W[t - 16];
	}

	u32 a = (ctx -> hash.sha256_32_t)[0];
	u32 b = (ctx -> hash.sha256_32_t)[1];
	u32 c = (ctx -> hash.sha256_32_t)[2];
	u32 d = (ctx -> hash.sha256_32_t)[3];
	u32 e = (ctx -> hash.sha256_32_t)[4];
	u32 f = (ctx -> hash.sha256_32_t)[5];
	u32 g = (ctx -> hash.sha256_32_t)[6];
	u32 h = (ctx -> hash.sha256_32_t)[7];

	for (unsigned int t = 0; t < 64; ++t) {   
		const u32 T1 = h + BSIG1_256(e) + CH(e, f, g) + costants_256[t] + W[t];
		const u32 T2 = BSIG0_256(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	(ctx -> hash.sha256_32_t)[0] += a;
	(ctx -> hash.sha256_32_t)[1] += b;
	(ctx -> hash.sha256_32_t)[2] += c;
	(ctx -> hash.sha256_32_t)[3] += d;
	(ctx -> hash.sha256_32_t)[4] += e;
	(ctx -> hash.sha256_32_t)[5] += f;
	(ctx -> hash.sha256_32_t)[6] += g;
	(ctx -> hash.sha256_32_t)[7] += h;

	mem_cpy(ctx -> msg_block, ctx -> msg_block + SHA256_BLOCK_SIZE_IN_BYTES, SHA256_BLOCK_SIZE_IN_BYTES);
	mem_set(ctx -> msg_block + SHA256_BLOCK_SIZE_IN_BYTES, 0, SHA256_BLOCK_SIZE_IN_BYTES);
	ctx -> msg_block_size -= SHA256_BLOCK_SIZE_IN_BYTES;

	return;
}

static void pad_block_256(sha_ctx* ctx) {
	u64 last_block_len = ctx -> msg_block_size;
	u64 k = (448 - ((ctx -> msg_block_size * 8 + 1) % SHA256_BLOCK_SIZE)) % SHA512_BLOCK_SIZE;
	unsigned int blocks_cnt = (last_block_len * 8 + 1 + k + SHA256_BLOCK_SIZE_IN_BYTES) / SHA256_BLOCK_SIZE;
	ctx -> msg_block_size = blocks_cnt * SHA256_BLOCK_SIZE_IN_BYTES;
	
	(ctx -> msg_block)[last_block_len] = 0x80;
	
	u64 l = ctx -> total_msg_size * 8;
	((u32*) (ctx -> msg_block))[ctx -> msg_block_size / 4 - 2] = (l >> 32) & 0xFFFFFFFF;	
	((u32*) (ctx -> msg_block))[ctx -> msg_block_size / 4 - 1] = l & 0xFFFFFFFF;	
	KOCKET_BE_CONVERT(((u32*) (ctx -> msg_block)) + (ctx -> msg_block_size / 4 - 2), 4);
	KOCKET_BE_CONVERT(((u32*) (ctx -> msg_block)) + (ctx -> msg_block_size / 4 - 1), 4);

	return;
}

int sha256_update(sha_ctx* ctx, const u8* data, const u64 len) {
	if (ctx -> is_finished) return -KOCKET_UPDATING_FINISHED_CTX;

	u64 copied_size = MIN(len, SHA256_BLOCK_SIZE_IN_BYTES - ctx -> msg_block_size);
	mem_cpy(ctx -> msg_block + ctx -> msg_block_size, data, copied_size);
	ctx -> msg_block_size += copied_size;

	u64 offset = copied_size;
	while (ctx -> msg_block_size >= SHA256_BLOCK_SIZE_IN_BYTES) {
		process_block_256(ctx);	
		
		if (offset < len) {
			copied_size = MIN(len - offset, SHA256_BLOCK_SIZE_IN_BYTES - ctx -> msg_block_size);
			mem_cpy(ctx -> msg_block + ctx -> msg_block_size, data + offset, copied_size);
			ctx -> msg_block_size += copied_size;
			offset += copied_size;
		}
	}

	ctx -> total_msg_size += len;

	return KOCKET_NO_ERROR;
}

static int __sha256_final(sha_t* digest, sha_ctx* ctx, const bool use_le) {
	if (ctx -> is_finished) return -KOCKET_UPDATING_FINISHED_CTX;
	
	pad_block_256(ctx);
	
	do {
		process_block_256(ctx);
	} while (ctx -> msg_block_size);
	
	(digest -> sha256_32_t)[0] = (ctx -> hash.sha256_32_t)[7];
	(digest -> sha256_32_t)[1] = (ctx -> hash.sha256_32_t)[6];
	(digest -> sha256_32_t)[2] = (ctx -> hash.sha256_32_t)[5];
	(digest -> sha256_32_t)[3] = (ctx -> hash.sha256_32_t)[4];
	(digest -> sha256_32_t)[4] = (ctx -> hash.sha256_32_t)[3];
	(digest -> sha256_32_t)[5] = (ctx -> hash.sha256_32_t)[2];
	(digest -> sha256_32_t)[6] = (ctx -> hash.sha256_32_t)[1];
	(digest -> sha256_32_t)[7] = (ctx -> hash.sha256_32_t)[0];
	
	if (!use_le) KOCKET_BE_CONVERT(digest -> sha256_t, SHA256_DIGEST_SIZE);
	
	ctx -> is_finished = TRUE;

	return KOCKET_NO_ERROR;
}

int sha256_final_le(sha_t* digest, sha_ctx* ctx) {
   	return __sha256_final(digest, ctx, TRUE);
}

int sha256_final(sha_t* digest, sha_ctx* ctx) {
	return __sha256_final(digest, ctx, FALSE);
}

static void __sha256(const u8* data, const u64 len, sha_t* digest, const bool use_le) {
	sha_ctx ctx = {0};
	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	__sha256_final(digest, &ctx, use_le);
	return;
}

void sha256_le(const u8* data, const u64 len, sha_t* digest) {
	__sha256(data, len, digest, TRUE);
	return;
}

void sha256(const u8* data, const u64 len, sha_t* digest) {
	__sha256(data, len, digest, FALSE);
	return;
}

// -----------------------
//  Test SHA-256
// -----------------------
int test_sha256(void) {
	sha_t hash = {0};
	sha_t hash_le = {0};
	
	const u8 data[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	printf("Testing SHA-256:\n");
	sha256(data, KOCKET_ARR_SIZE(data) - 1, &hash);
	sha256_le(data, KOCKET_ARR_SIZE(data) - 1, &hash_le);

	static const sha_t test_sha_le = {
		.sha256_t = {
			0xD1, 0xE9, 0xFE, 0x7A, 0x03, 0x45, 0xAC, 0xAF, 
			0x51, 0x7A, 0xF0, 0xE8, 0x11, 0x9B, 0x24, 0x0B, 
			0x37, 0x92, 0x04, 0x7B, 0x9E, 0xE5, 0x6C, 0x03, 
			0x80, 0x83, 0xAF, 0x78, 0xA7, 0x16, 0x5B, 0xCF
		}
	};
	
	sha_t test_sha = {0};
	mem_cpy(test_sha.sha256_t, test_sha_le.sha256_t, sizeof(test_sha.sha256_t));
	KOCKET_BE_CONVERT(test_sha.sha256_t, sizeof(test_sha.sha256_t));

	if (mem_cmp(hash.sha256_t, test_sha.sha256_t, sizeof(test_sha.sha256_t))) {
		printf("Failed test sha256.\n");
		printf("HASHED: \n");
		PRINT_HASH(hash);
		printf("Expected: \n");
		PRINT_HASH(test_sha);
		return 1;
	}

	PRINT_HASH(hash);
	PRINT_HASH(test_sha);
	
	if (mem_cmp(hash_le.sha256_t, test_sha_le.sha256_t, sizeof(test_sha_le.sha256_t))) {
		printf("Failed test sha256.\n");
		printf("HASHED: \n");
		PRINT_HASH(hash_le);
		printf("Expected: \n");
		PRINT_HASH(test_sha_le);
		return 1;
	}

	PRINT_HASH(hash_le);
	PRINT_HASH(test_sha_le);
	
	printf("\n -------- Test sha256 multi update  ----------\n\n");
	
	sha_ctx ctx = {0};
	sha256_init(&ctx);

	const unsigned int splits[] = { 127, 2, 1, 128, 17, 300, 193 };
	unsigned char test_data_be[768] = {0};
	mem_cpy(test_data_be, test_data, 768);
	KOCKET_BE_CONVERT(test_data_be, 768);

	sha_t digest = {0};
	unsigned int offset = 0;
	for (unsigned int i = 0; i < KOCKET_ARR_SIZE(splits); ++i) {
		sha256_update(&ctx, test_data_be + offset, splits[i]);
		PRINT_HASH(ctx.hash);
		offset += splits[i];
	}

	sha256_final(&digest, &ctx);
	PRINT_HASH(digest);

	sha_t digest_two = {0};
	sha256(test_data_be, KOCKET_ARR_SIZE(test_data_be), &digest_two);
	PRINT_HASH(digest_two);

	if (mem_cmp(digest.sha256_t, digest_two.sha256_t, sizeof(digest.sha256_t))) {
		WARNING_LOG("digest mismatch");
		return -1;
	}
	
	return KOCKET_NO_ERROR;
}

#endif //_SHA256_H_

