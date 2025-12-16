#include <stdio.h>
#include <stdlib.h>

#include "x25519.h"
#include "ed25519.h"
#include "poly1305.h"
#include "hkdf.h"
#include "sha512.h"

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
	
	printf("Testing X25519 (with check test):\n");
	if ((ret = test_x25519(TRUE))) {
		printf("ERROR::%s: while testing X25519.\n", kocket_status_str[-ret]);
		return ret;
	}
	
	printf("\n-----------------------------------------\n\n");
	
	printf("Testing X25519 (with random data):\n");
	if ((ret = test_x25519(FALSE))) {
		printf("ERROR::%s: while testing X25519.\n", kocket_status_str[-ret]);
		return ret;
	}
	
	printf("\n-----------------------------------------\n\n");
	
	printf("Testing HKDF:\n");
	if ((ret = test_hkdf())) {
		printf("ERROR::%s: while testing HKDF.\n", kocket_status_str[-ret]);
		return ret;
	}
	
	printf("\n-----------------------------------------\n\n");
	
	printf("Testing POLY1305:\n");
	if ((ret = poly1305(NULL))) {
		printf("ERROR::%s: while testing POLY1305.\n", kocket_status_str[-ret]);
		return ret;
	}
	
	return 0;
}

