/*
 * Copyright (C) 2025 TheProgxy <theprogxy@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _CHACHA20_H_
#define _CHACHA20_H_

#ifdef _K_KOCKET_H_
	#include <linux/random.h>
	#define kocket_srand() 
	#define kocket_rand get_random_u64
#else
	#include <time.h>
	#define kocket_srand() srand(time(NULL))

	static inline u64 kocket_rand(void) {
		u32 base = rand();
	   	u64 upper = rand();
		return ((upper << 32) | base);
	}

#endif //_K_KOCKET_H_

// --------
//  Macros
// --------
#if __has_builtin(__builtin_stdc_rotate_left)
	#define ROTL __builtin_stdc_rotate_left
#elif __has_builtin(__builtin_rotateleft32) 
	#define ROTL __builtin_rotateleft32
#else
	#define ROTL(x,r) (((x) << (r)) | ((x) >> (32 - (r))))
#endif

// TODO: Clean up and refactor a bit....
typedef u8  cct_key_t[32];
typedef u64 cct_key_64_t[4];
typedef u8  cct_nonce_t[12];
typedef u32 cct_nonce_32_t[3];
typedef u8  cct_rand_t[64];
typedef u32 cct_state_t[16];

#define CHACHA20_BLOCK_SIZE 64

/* -------------------------------------------------------------------------------------------------------- */
// ------------------------ 
//  Functions Declarations
// ------------------------ 
static inline void is_rdseed_supported(void);
static inline void is_rdrand_supported(void);
NO_INLINE static u64 get_rand64(void);
NO_INLINE static u32 get_seed32(void);
void chacha20_block(const cct_key_t key, const u32 counter, const cct_nonce_t nonce, cct_rand_t random_data);
u8* chacha20_randomize(cct_rand_t random_data);
u8* chacha20_encrypt(u8* encrypted_message, const cct_key_t key, const u32 counter, const cct_nonce_t nonce, const u8* plaintext, const u64 plaintext_size);

/* -------------------------------------------------------------------------------------------------------- */
// ------------------ 
//  Static Variables 
// ------------------ 
static int rdseed_support = FALSE;
static int rdrand_support = FALSE;

static inline void is_rdseed_supported(void) {
	int is_supported = 0; 
	int cpuid_feature = 7;
	int sub_cpuid_feature = 0;
	
	__asm__ volatile (                          
		"cpuid\n\t"                                
		: "=b"(is_supported)     
		: "a"(cpuid_feature), "c"(sub_cpuid_feature)
	);      
	
	rdseed_support = (is_supported >> 18) & 0x01; 
	
	return;
}

static inline void is_rdrand_supported(void) {
    int is_supported = 0; 
	int cpuid_feature = 1;
	
	__asm__ volatile (                         
        "cpuid\n\t"                              
        : "=c"(is_supported)                   
        : "a"(cpuid_feature)
	);                     
    
	rdrand_support = (is_supported >> 30) & 0x01; 
	
	return;
}

NO_INLINE static u32 get_seed32(void) {
    if (!rdseed_support) {
		return ((u32) kocket_rand());
	}
	
	u32 seed = 0;
	do {
		__asm__ volatile(
			"kocket_get_seed:\n\t"
			"rdseed %[seed]\n\t"
			"jnc kocket_get_seed\n\t"
			: [seed] "=r"(seed)
		);
	} while (seed == 0);

    return seed;
}

NO_INLINE static u64 get_rand64(void) {
	if (!rdrand_support) {
		return ((u64) kocket_rand());
	}
	
	static u64 previous_rand = 0;
	u64 rand = 0;
	do {
		__asm__ volatile(
			"kocket_get_rand:\n\t"
			"rdrand %[rand]\n\t"
			"jnc kocket_get_rand\n\t"
			: [rand] "=r"(rand)
		);
	} while (rand == previous_rand || rand == 0);
	
	previous_rand = rand ^ get_seed32() ^ previous_rand;

	return previous_rand;
}

#define PRINT_CCT_RAND(rand) print_cct_rand(rand, #rand)
static void print_cct_rand(const cct_rand_t rand, const char* name) {
	printf("%s: ", name);
	for (int i = 63; i >= 0; --i) printf("%02X", rand[i]);
	printf("\n");
	return;
}

#define PRINT_CCT_KEY(key) print_cct_key(key, #key)
UNUSED_FUNCTION static void print_cct_key(const cct_key_t key, const char* name) {
	printf("%s: ", name);
	for (int i = 31; i >= 0; --i) printf("%02X", key[i]);
	printf("\n");
	return;
}

#define PRINT_CCT_STATE(state) print_cct_state(state, #state)
UNUSED_FUNCTION static void print_cct_state(const cct_state_t state, const char* name) {
	printf("%s:\n", name);
	for (int i = 15; i >= 0; i -= 4) {
		printf("%08X, %08X, %08X, %08X\n", state[i], state[i - 1], state[i - 2], state[i - 3]);
	}
	printf("\n");
	return;
}

static inline void quarter_round(u32* a, u32* b, u32* c, u32* d) {
	*a += *b; *d ^= *a; *d = ROTL(*d, 16); 
	*c += *d; *b ^= *c; *b = ROTL(*b, 12);
	*a += *b; *d ^= *a; *d = ROTL(*d, 8);
	*c += *d; *b ^= *c; *b = ROTL(*b, 7);
	return;
}

static inline void inner_block(cct_state_t state) {
	quarter_round(state + 15, state + 11, state + 7, state + 3);
	quarter_round(state + 14, state + 10, state + 6, state + 2);
	quarter_round(state + 13, state + 9,  state + 5, state + 1);
	quarter_round(state + 12, state + 8,  state + 4, state + 0);
	quarter_round(state + 15, state + 10, state + 5, state + 0);
	quarter_round(state + 14, state + 9,  state + 4, state + 3);
	quarter_round(state + 13, state + 8,  state + 7, state + 2);
	quarter_round(state + 12, state + 11, state + 6, state + 1);
	return;
}

void chacha20_block(const cct_key_t key, const u32 counter, const cct_nonce_t nonce, cct_rand_t random_data) {
	cct_state_t chacha_initial_vector = {0};
	
	// Init the initial state vector
	chacha_initial_vector[15] = 0x61707865;
	chacha_initial_vector[14] = 0x3320646E;
    chacha_initial_vector[13] = 0x79622D32; 
	chacha_initial_vector[12] = 0x6B206574;
	mem_cpy(chacha_initial_vector + 4, key, sizeof(cct_key_t));
	chacha_initial_vector[3] = counter;
	mem_cpy(chacha_initial_vector, nonce, sizeof(cct_nonce_t));

	cct_state_t chacha_working_vector = {0};
	mem_cpy(chacha_working_vector, chacha_initial_vector, sizeof(cct_state_t));

	for (u8 i = 0; i < 10; ++i) inner_block(chacha_working_vector);
	
	for (u8 i = 0; i < 16; ++i) chacha_initial_vector[i] += chacha_working_vector[i];
	
	mem_cpy(random_data, chacha_initial_vector, sizeof(cct_rand_t));

	for (u8 i = 0; i < 16; ++i) KOCKET_BE_CONVERT(((u32*) random_data) + i, sizeof(u32));

	return;
}

u8* chacha20_randomize(cct_rand_t random_data) {
	static u32 block_count = 0;
	cct_key_64_t key = {0};
	cct_nonce_32_t nonce = {0};
	mem_set(random_data, 0, 64);

	is_rdseed_supported();
    is_rdrand_supported();
	
	if (!rdrand_support) {
        WARNING_LOG("CHACHA20: RDRAND is UNSUPPORTED.");
        if (!rdseed_support) WARNING_LOG("CHACHA20: RDSEED is UNSUPPORTED.");
        kocket_srand();
    } else if (!rdseed_support) {
		DEBUG_LOG("CHACHA20: RDSEED is UNSUPPORTED.");
	}

	for (u8 i = 0; i < 4; ++i) {
		key[i] = get_rand64();
		if (i < 3) nonce[i] = get_seed32();
	}

	chacha20_block((u8*) key, block_count, (u8*) nonce, random_data);

	// Update the block count
	block_count++;

	return random_data; 
}

u8* chacha20_encrypt(u8* encrypted_message, const cct_key_t key, const u32 counter, const cct_nonce_t nonce, const u8* plaintext, const u64 plaintext_size) {
	u64 j = 0;
	u64 encrypted_message_idx = 0;
	for (j = 0; j < (plaintext_size / 64); ++j) {
		cct_rand_t key_stream = {0};
		chacha20_block(key, counter + j, nonce, key_stream);
		for (unsigned int i = 0; i < CHACHA20_BLOCK_SIZE; ++i) {
			encrypted_message[encrypted_message_idx++] = plaintext[j * 64 + i] ^ key_stream[i];
		}
	}

	const unsigned int leftover = plaintext_size % 64;
	if (leftover) {
		cct_rand_t key_stream = {0};
		chacha20_block(key, counter + j, nonce, key_stream);
		for (unsigned int i = 0; i < leftover; ++i) {
			encrypted_message[encrypted_message_idx++] = plaintext[j * 64 + i] ^ key_stream[i];
		}
	}
	
	return encrypted_message; 
}

int test_chacha20(void) {
	const cct_key_t key = {
		0x1C, 0x1D, 0x1E, 0x1F,
		0x18, 0x19, 0x1A, 0x1B,
	   	0x14, 0x15, 0x16, 0x17,
		0x10, 0x11, 0x12, 0x13,
		0x0C, 0x0D, 0x0E, 0x0F,
	   	0x08, 0x09, 0x0A, 0x0B,
		0x04, 0x05, 0x06, 0x07,
		0x00, 0x01, 0x02, 0x03	
	};

	const cct_nonce_t nonce = {
		0x00, 0x00, 0x00, 0x00,
	   	0x00, 0x00, 0x00, 0x4A,
		0x00, 0x00, 0x00, 0x09
	};

	const cct_rand_t rd_exp = {
		0x4E, 0x3C, 0x50, 0xA2, 0xE8, 0x83, 0xD0, 0xCB,
	   	0xB9, 0x4E, 0x16, 0xDE, 0xD1, 0x9C, 0x12, 0xB5, 
		0xA2, 0x02, 0x8B, 0xD9, 0x05, 0xD7, 0xC2, 0x14,
	   	0x09, 0xAA, 0x9F, 0x07, 0x46, 0x64, 0x82, 0xD2,
	   	0x4E, 0x6C, 0xD4, 0xC3, 0x9A, 0xAA, 0x22, 0x04, 
		0x03, 0x68, 0xC0, 0x33, 0xC7, 0xF4, 0xD1, 0xC7, 
		0xC4, 0x71, 0x20, 0xA3, 0x1F, 0xDD, 0x0F, 0x50, 
		0x15, 0x59, 0x3B, 0xD1, 0xE4, 0xE7, 0xF1, 0x10
	};

	cct_rand_t rd = {0};
	printf("Test chacha20_block:\n");
	chacha20_block(key, 1, nonce, rd);
	
	if (mem_cmp(rd, rd_exp, sizeof(rd))) {
		PRINT_CCT_RAND(rd);
		PRINT_CCT_RAND(rd_exp);
		WARNING_LOG("Failed testing chacha20_block.");
		return 1;
	}

	TODO("Implement me with RFC Test Vectors");
	return -KOCKET_TODO;
}

#endif // _CHACHA20_H_

