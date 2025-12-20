#include <stdio.h>
#include <stdlib.h>

#include "x25519.h"
#include "ed25519.h"
#include "poly1305.h"
#include "hkdf.h"
#include "common_sha.h"

int main() {
	int ret = 0;
	/* if (test_sha512()) return 1; */
	/* if (test_sha256()) return 1; */
	
	/* printf("\n-----------------------------------------\n\n"); */

	/* u8 data[] = "abcdefghi"; */
	/* printf("Testing ED25519 (null message with checks):\n"); */
	/* if ((ret = test_ed25519(NULL, 0))) { */
	/* 	if (ret < 0) printf("ERROR::%s: while testing ED25519.\n", kocket_status_str[-ret]); */
	/* 	else printf("ERROR: while testing ED25519.\n"); */
	/* 	return ret; */
	/* } */
	
	/* printf("\n-----------------------------------------\n\n"); */

	/* printf("Testing ED25519 (with message):\n"); */
	/* if ((ret = test_ed25519(data, sizeof(data) - 1))) { */
	/* 	if (ret < 0) printf("ERROR::%s: while testing ED25519.\n", kocket_status_str[-ret]); */
	/* 	else printf("ERROR: while testing ED25519.\n"); */
	/* 	return ret; */
	/* } */
	
	/* printf("\n-----------------------------------------\n\n"); */
	
	/* printf("Testing X25519 (with check test):\n"); */
	/* if ((ret = test_x25519(TRUE))) { */
	/* 	if (ret < 0) printf("ERROR::%s: while testing X25519.\n", kocket_status_str[-ret]); */
	/* 	else printf("ERROR: while testing X25519.\n"); */
	/* 	return ret; */
	/* } */
	
	/* printf("\n-----------------------------------------\n\n"); */
	
	/* printf("Testing X25519 (with random data):\n"); */
	/* if ((ret = test_x25519(FALSE))) { */
	/* 	if (ret < 0) printf("ERROR::%s: while testing X25519.\n", kocket_status_str[-ret]); */
	/* 	else printf("ERROR: while testing X25519.\n"); */
	/* 	return ret; */
	/* } */
	
	/* printf("\n-----------------------------------------\n\n"); */
	
	/* printf("Testing HKDF:\n"); */
	/* if ((ret = test_hkdf())) { */
	/* 	if (ret < 0) printf("ERROR::%s: while testing HKDF.\n", kocket_status_str[-ret]); */
	/* 	else printf("ERROR: while testing HKDF.\n"); */
	/* 	return ret; */
	/* } */
	
	/* printf("\n-----------------------------------------\n\n"); */
	
	printf("Testing CHACHA20:\n");
	if ((ret = test_chacha20())) {
		if (ret < 0) printf("ERROR::%s: while testing CHACHA20.\n", kocket_status_str[-ret]);
		else printf("ERROR: while testing CHACHA20.\n");
		return ret;
	}
	
	printf("\n-----------------------------------------\n\n");
	
	printf("Testing POLY1305:\n");
	if ((ret = test_poly1305(NULL, 0))) {
		if (ret < 0) printf("ERROR::%s: while testing POLY1305.\n", kocket_status_str[-ret]);
		else printf("ERROR: while testing POLY1305.\n");
		return ret;
	}
	
	return 0;
}

