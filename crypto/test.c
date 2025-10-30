#include <stdio.h>
#include <stdlib.h>

#include "x25519.h"
#include "ed25519.h"
#include "poly1305.h"
#include "sha512.h"

int main() {
	int ret = 0;
	
	u64 hash[8] = {0};
	u8 data[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	printf("Testing SHA-512:\n");
	if ((ret = sha512(data, sizeof(data) - 1, hash))) {
		printf("ERROR::%s: while testing SHA-512.\n", kocket_status_str[-ret]);
		return ret;
	}

	const u64 test_sha[] = {
		0x8E959B75DAE313DA,  
		0x8CF4F72814FC143F,
		0x8F7779C6EB9F7FA1, 
		0x7299AEADB6889018, 
		0x501D289E4900F7E4,
		0x331B99DEC4B5433A,
	   	0xC7D329EEB6DD2654, 
		0x5E96E55B874BE909 
	};

	if (mem_cmp(hash, test_sha, sizeof(test_sha))) {
		printf("Failed test sha512.\n");
		printf("HASHED: \n");
		print_hash((u8*) hash);
		printf("Expected: \n");
		print_hash((u8*) test_sha);
		return 1;
	}

	print_hash((u8*) hash);

	printf("Testing ED25519:\n");
	if ((ret = ed25519(NULL))) {
		printf("ERROR::%s: while testing ED25519.\n", kocket_status_str[-ret]);
		return ret;
	}
	
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

