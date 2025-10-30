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
	/* "Hi mom, I feel well again!"; */
	printf("Testing SHA-512:\n");
	if ((ret = sha512(data, sizeof(data) - 1, hash))) {
		printf("ERROR::%s: while testing SHA-512.\n", kocket_status_str[-ret]);
		return ret;
	}

	print_hash(hash);

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

