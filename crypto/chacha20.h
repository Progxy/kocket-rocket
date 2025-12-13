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
#define QUARTER_ROUND(a, b, c, d) \
	a += b; d ^= a; d <<= 16; 	  \
	c += d; b ^= c; b <<= 12;     \
	a += b; d ^= a; d <<= 8;      \
	c += d; b ^= c; b <<= 7;

/* -------------------------------------------------------------------------------------------------------- */
// ------------------------ 
//  Functions Declarations
// ------------------------ 
static inline void is_rdseed_supported(void);
static inline void is_rdrand_supported(void);
NO_INLINE static u64 get_rand64(void);
NO_INLINE static u32 get_seed32(void);
void cha_cha20_randomize(u8 key[256], u8 nonce[96], u8 random_data[64]);
u8* cha_cha20(u8 random_data[64]);

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

void cha_cha20_randomize(u8 key[256], u8 nonce[96], u8 random_data[64]) {
	static u32 block_count = 0;
	u32 chacha_initial_vector[16] = {0};
	
	// Init the initial state vector
	chacha_initial_vector[0] = 0x61707865;
	chacha_initial_vector[1] = 0x3320646e;
    chacha_initial_vector[2] = 0x79622d32; 
	chacha_initial_vector[3] = 0x6b206574;
	for (u8 i = 0; i < 8; ++i) chacha_initial_vector[i + 4] = ((u32*) key)[i];	
	chacha_initial_vector[12] = block_count;
	for (u8 i = 0; i < 3; ++i) chacha_initial_vector[i + 13] = ((u32*) nonce)[i];

	u32 chacha_working_vector[16] = {0};
	for (u8 i = 0; i < 16; ++i) chacha_working_vector[i] = chacha_initial_vector[i];

	for (u8 i = 0; i < 10; ++i) {
		QUARTER_ROUND(chacha_working_vector[0], chacha_working_vector[4], chacha_working_vector[8], chacha_working_vector[12]);
		QUARTER_ROUND(chacha_working_vector[1], chacha_working_vector[5], chacha_working_vector[9], chacha_working_vector[13]);
		QUARTER_ROUND(chacha_working_vector[2], chacha_working_vector[6],chacha_working_vector[10], chacha_working_vector[14]);
		QUARTER_ROUND(chacha_working_vector[3], chacha_working_vector[7],chacha_working_vector[11], chacha_working_vector[15]);
		QUARTER_ROUND(chacha_working_vector[0], chacha_working_vector[5],chacha_working_vector[10], chacha_working_vector[15]);
		QUARTER_ROUND(chacha_working_vector[1], chacha_working_vector[6],chacha_working_vector[11], chacha_working_vector[12]);
		QUARTER_ROUND(chacha_working_vector[2], chacha_working_vector[7], chacha_working_vector[8], chacha_working_vector[13]);
		QUARTER_ROUND(chacha_working_vector[3], chacha_working_vector[4], chacha_working_vector[9], chacha_working_vector[14]);
	}

	for (u8 i = 0; i < 16; ++i) chacha_initial_vector[i] += chacha_working_vector[i];
	mem_cpy(random_data, chacha_initial_vector, 64 * sizeof(u8));

	// Update the block count
	block_count++;

	return;
}

u8* cha_cha20(u8 random_data[64]) {
	u64 key[64] = {0};
	u32 nonce[24] = {0};
	mem_set(random_data, 0, 64 * sizeof(u8));

	is_rdseed_supported();
    is_rdrand_supported();
	if (!rdrand_support) {
        WARNING_LOG("CHACHA20: RDRAND is UNSUPPORTED.");
        if (!rdseed_support) WARNING_LOG("CHACHA20: RDSEED is UNSUPPORTED.");
        kocket_srand();
    } else if (!rdseed_support) {
		DEBUG_LOG("CHACHA20: RDSEED is UNSUPPORTED.");
	}

	for (u8 i = 0; i < 64; ++i) {
		key[i] = get_rand64();
		if (i < 24) nonce[i] = get_seed32();
	}

	cha_cha20_randomize((u8*) key, (u8*) nonce, random_data);

	return random_data; 
}

#endif // _CHACHA20_H_

