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

#define QUARTER_ROUND(a, b, c, d) \
	a += b; d ^= a; d <<= 16; 	  \
	c += d; b ^= c; b <<= 12;     \
	a += b; d ^= a; d <<= 8;      \
	c += d; b ^= c; b <<= 7;

static inline int is_rdseed_supported(void) {
	int is_supported = 0; 
	__asm__ volatile (                          
		 "movl $7, %%eax;"                       
		 "cpuid;"                                
		 "movl %%ebx, %0;"                       
		 : "=r"(is_supported)                    
		 :                                       
		 : "%eax", "%ebx");                      
	return (is_supported >> 18) & 0x01; 
}

static inline int is_rdrand_supported(void) {
    int is_supported = 0; 
	__asm__ volatile (                         
         "movl $1, %%eax;"                      
         "cpuid;"                              
         "movl %%ecx, %0;"                      
         : "=r"(is_supported)                   
         :                                      
         : "%eax", "%ecx");                     
    return (is_supported >> 30) & 0x01; 
}

static u64 get_rand64(void) {
    u64 rand = 0;
    __asm__ volatile(
        "gen_rand:"
        "rdrand %0;"
        "jnc gen_rand;"
        : "=r"(rand)
        :          );
    return rand;
}

static u32 get_seed32(int is_rdseed_supported) {
    if (!is_rdseed_supported) return ((u32) get_rand64());
	u32 seed = 0;
    __asm__ volatile(
        "gen_seed:"
        "rdseed %0;"
        "jnc gen_seed;"
        : "=r"(seed)
        :          );
    return seed;
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

	int is_supported_rdseed = is_rdseed_supported();
    int is_supported_rdrand = is_rdrand_supported();
    if (!is_supported_rdrand) {
        WARNING_LOG("CHACHA20: RDRAND is UNSUPPORTED.\n");
        if (!is_supported_rdseed) WARNING_LOG("CHACHA20: RDSEED is UNSUPPORTED.\n");
        srand(time(NULL));
		u32 rand_value = rand();
		mem_cpy(random_data, &rand_value, sizeof(u32));
		rand_value = rand();
		mem_cpy(random_data + sizeof(u32), &rand_value, sizeof(u32));
		return random_data;
    } else if (!is_supported_rdseed) DEBUG_LOG("CHACHA20: RDSEED is UNSUPPORTED.\n");

	for (u8 i = 0; i < 64; ++i) {
		key[i] = get_rand64();
		if (i < 24) nonce[i] = get_seed32(is_supported_rdseed);
	}

	cha_cha20_randomize((u8*) key, (u8*) nonce, random_data);

	return random_data; 
}

#endif // _CHACHA20_H_

