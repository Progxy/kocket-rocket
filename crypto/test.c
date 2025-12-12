#include <stdio.h>
#include <stdlib.h>

#include "x25519.h"
#include "ed25519.h"
#include "poly1305.h"
#include "sha512.h"

int test_sha512(void) {
	int ret = 0;
	sha512_64_t hash = {0};
	sha512_64_t hash_le = {0};
	
	u8 data[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	printf("Testing SHA-512:\n");
	if ((ret = sha512(data, sizeof(data) - 1, hash))) {
		printf("ERROR::%s: while testing SHA-512.\n", kocket_status_str[-ret]);
		return ret;
	}

	if ((ret = sha512_le(data, sizeof(data) - 1, hash_le))) {
		printf("ERROR::%s: while testing SHA-512.\n", kocket_status_str[-ret]);
		return ret;
	}

	static const sha512_t test_sha_le = {
		0x09, 0xE9, 0x4B, 0x87, 0x5B, 0xE5, 0x96, 0x5E,
		0x54, 0x26, 0xDD, 0xB6, 0xEE, 0x29, 0xD3, 0xC7,
		0x3A, 0x43, 0xB5, 0xC4, 0xDE, 0x99, 0x1B, 0x33,
		0xE4, 0xF7, 0x00, 0x49, 0x9E, 0x28, 0x1D, 0x50,
		0x18, 0x90, 0x88, 0xB6, 0xAD, 0xAE, 0x99, 0x72,
		0xA1, 0x7F, 0x9F, 0xEB, 0xC6, 0x79, 0x77, 0x8F,
		0x3F, 0x14, 0xFC, 0x14, 0x28, 0xF7, 0xF4, 0x8C,
		0xDA, 0x13, 0xE3, 0xDA, 0x75, 0x9B, 0x95, 0x8E
	};
	
	sha512_t test_sha = {0};
	mem_cpy(test_sha, test_sha_le, sizeof(sha512_t));
	KOCKET_BE_CONVERT(test_sha, sizeof(sha512_t));

	if (mem_cmp(hash, test_sha, sizeof(test_sha))) {
		printf("Failed test sha512.\n");
		printf("HASHED: \n");
		PRINT_HASH((u8*) hash);
		printf("Expected: \n");
		PRINT_HASH((u8*) test_sha);
		return 1;
	}

	PRINT_HASH((u8*) hash);
	PRINT_HASH((u8*) test_sha);
	
	if (mem_cmp(hash_le, test_sha_le, sizeof(test_sha))) {
		printf("Failed test sha512.\n");
		printf("HASHED: \n");
		PRINT_HASH((u8*) hash_le);
		printf("Expected: \n");
		PRINT_HASH((u8*) test_sha_le);
		return 1;
	}

	PRINT_HASH((u8*) hash_le);
	PRINT_HASH((u8*) test_sha_le);
	
	return 0;
}

int main() {
	int ret = 0;
	if (test_sha512()) return 1;
	
	printf("\n-----------------------------------------\n\n");

	u8 data[] = "abcdefghi";
	printf("Testing ED25519 (null message with checks):\n");
	if ((ret = test_ed25519(NULL, 0))) {
		printf("ERROR::%s: while testing ED25519.\n", kocket_status_str[-ret]);
		return ret;
	}
	
	printf("\n-----------------------------------------\n\n");

	printf("Testing ED25519 (with message):\n");
	if ((ret = test_ed25519(data, sizeof(data) - 1))) {
		printf("ERROR::%s: while testing ED25519.\n", kocket_status_str[-ret]);
		return ret;
	}
	
	printf("\n-----------------------------------------\n\n");
	
	printf("Testing X25519:\n");
	if ((ret = x25519(NULL))) {
		printf("ERROR::%s: while testing X25519.\n", kocket_status_str[-ret]);
		return ret;
	}
	
	printf("Testing POLY1305:\n");
	if ((ret = poly1305(NULL))) {
		printf("ERROR::%s: while testing POLY1305.\n", kocket_status_str[-ret]);
		return ret;
	}

	return 0;
}

