#ifndef _SHA512_H_
#define _SHA512_H_

#define _KOCKET_SPECIAL_TYPE_SUPPORT_
#define _KOCKET_UTILS_IMPLEMENTATION_
#define _KOCKET_PRINTING_UTILS_
#include "../kocket_utils.h"

/* Reference: [RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234) */

// TODO: Refactor/Clean the code...

// Constant Values
#define BLOCK_SIZE 			1024
#define BLOCK_SIZE_IN_BYTES 128

// Macros Functions
#if __has_builtin(__builtin_stdc_rotate_right)
	#define ROTR __builtin_stdc_rotate_right
#elif __has_builtin(__builtin_rotateright64) 
	#define ROTR __builtin_rotateright64
#else
	#define ROTR(x, r) (((x) >> (r)) | ((x) << (64 - (r))))
#endif

#define CH(x, y, z)  (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)     (ROTR((x), 28) ^ ROTR((x), 34) ^ ROTR((x), 39))
#define BSIG1(x)     (ROTR((x), 14) ^ ROTR((x), 18) ^ ROTR((x), 41))
#define SSIG0(x)     (ROTR((x), 1)  ^ ROTR((x), 8)  ^ ((x) >> 7))
#define SSIG1(x)     (ROTR((x), 19) ^ ROTR((x), 61) ^ ((x) >> 6))

static const u64 costants[] = {
	0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
	0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
	0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
	0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
	0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
	0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
	0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
	0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
	0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
	0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
	0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
	0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
	0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
	0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
	0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
	0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
	0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
	0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
	0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
	0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
};

static void print_hash(u8* hash) {
	printf("hash: ");
	
	for (unsigned int i = 0; i < 8; ++i) {
		printf("%llX", ((u64*) hash)[i]);
	}
	
	printf("\n");
	
	return;
}

UNUSED_FUNCTION static void print_hexstr(u32* hex_str, u64 size) {
	printf("hex_str: \n");
	
	for (u64 i = 0; i < size / 4; ++i) {
		for (u8 t = 0; t < 4; ++t) printf("%02X", (hex_str[i] >> (t * 8)) & 0xFF);
		printf("%c", ((i % 4) != 3) ? ' ' : '\n');
	}

	printf("\n");
	
	return;
}

static u8* padding(u8* data, u64 len, int* blocks_cnt) {
	if (data == NULL) {
		*blocks_cnt = -KOCKET_INVALID_PARAMETERS;
		return NULL;
	}
	
	u64 k = (896 - ((len * 8 + 1) % 1024)) % 1024;
		
	*blocks_cnt = (len * 8 + 1 + k + 128) / BLOCK_SIZE;
	u64 new_size = *blocks_cnt * BLOCK_SIZE_IN_BYTES;
	
	u8* padded_data = kocket_calloc(new_size, 1);
	if (padded_data == NULL) {
		*blocks_cnt = -KOCKET_IO_ERROR;
		return NULL;
	}

	mem_cpy(padded_data, data, len);
	padded_data[len] = 0x80;
	((u64*) padded_data)[new_size / 8 - 2] = len >> 61;	
	((u64*) padded_data)[new_size / 8 - 1] = len * 8;	
	KOCKET_BE_CONVERT(((u64*) padded_data) + (new_size / 8 - 2), 8);
	KOCKET_BE_CONVERT(((u64*) padded_data) + (new_size / 8 - 1), 8);
	
	DEBUG_LOG("blocks_cnt: %d, k: %llu, new_size: %llu", *blocks_cnt, k, new_size);

	return padded_data;
}

int sha512(u8* data, u64 len, u64 hash[8]) {
	int blocks_cnt = 0;
	
	u8* padded_data = padding(data, len, &blocks_cnt);
	if (padded_data == NULL) {
		ERROR_LOG("Failed to pad the data.", kocket_status_str[-blocks_cnt]);
		return blocks_cnt;
	}

	for (u64 i = 0; i < (blocks_cnt * BLOCK_SIZE_IN_BYTES / 8ULL); ++i) {
		KOCKET_BE_CONVERT(padded_data + i * 8, 8);
	}
	
	hash[0] = 0x6A09E667F3BCC908;
    hash[1] = 0xBB67AE8584CAA73B;
    hash[2] = 0x3C6EF372FE94F82B;
    hash[3] = 0xA54FF53A5F1D36F1;
    hash[4] = 0x510E527FADE682D1;
    hash[5] = 0x9B05688C2B3E6C1F;
    hash[6] = 0x1F83D9ABFB41BD6B;
    hash[7] = 0x5BE0CD19137E2179;
	
	for (int i = 0; i < blocks_cnt; ++i) {
		u64 W[80] = {0};

		mem_cpy(W, padded_data + BLOCK_SIZE_IN_BYTES * i, BLOCK_SIZE_IN_BYTES);
		for (unsigned int t = 16; t < 80; ++t) {
			W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
		}

		u64 a = hash[0];
        u64 b = hash[1];
        u64 c = hash[2];
        u64 d = hash[3];
        u64 e = hash[4];
        u64 f = hash[5];
        u64 g = hash[6];
        u64 h = hash[7];
	
        for (unsigned int t = 0; t < 80; ++t) {   
			const u64 T1 = h + BSIG1(e) + CH(e, f, g) + costants[t] + W[t];
			const u64 T2 = BSIG0(a) + MAJ(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}
		
		hash[0] += a;
		hash[1] += b;
		hash[2] += c;
		hash[3] += d;
		hash[4] += e;
		hash[5] += f;
		hash[6] += g;
		hash[7] += h;
	}
	
	KOCKET_SAFE_FREE(padded_data);

	return KOCKET_NO_ERROR;
}

#endif //_SHA512_H_

