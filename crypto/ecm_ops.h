#ifndef _ECM_OPS_H_
#define _ECM_OPS_H_

#define CHONKY_ASSERT(cond) __ecm_assert(cond, #cond, __FILE__, __LINE__, __func__)

static void __ecm_assert(bool cond, const char* cond_str, const char* file, const unsigned int line, const char* func_name) {
	if (cond) return;

	WARNING_LOG(COLOR_STR("%s:%u: ", WARNING_COLOR) "Failed to assert the following condition: " COLOR_STR("'%s'", BLUE) " in function " COLOR_STR("'%s'", PURPLE), file, line, cond_str, func_name);
	abort();
	
	return;
}

#include "../deps/chonky_nums.h"

#define GET_SCALAR_BIT(val, n) ((((val).data[(((n) - ((n) % 8)) / 8)]) >> ((n) % 8)) & 0x01)

#define SCALAR_SIZE 64
#define LITTLE_SCALAR_SIZE 32
typedef struct {
	u8 data[SCALAR_SIZE];
} ECMScalar;

typedef struct ECMPoint {
	ECMScalar x;
	ECMScalar y;
	ECMScalar z;
	ECMScalar t;
} ECMPoint;

typedef struct ECMTempScalar {
	ECMScalar value;
	struct ECMTempScalar* next;
} ECMTempScalar;

/* NOTE:
 * A point (x,y) is represented in extended homogeneous coordinates 
 * (X, Y, Z, T), with x = X/Z, y = Y/Z, x * y = T/Z. 
 * The neutral point is (0,1), or equivalently in extended homogeneous 
 * coordinates (0, Z, Z, 0) for any non-zero Z.
*/

static const ECMPoint base_point = { 
	.x = {
		.data = {
			0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9, 0xB2, 0xA7, 0x25, 0x95,
			0x60, 0xC7, 0x2C, 0x69, 0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0,
			0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21
		}
	},
    
	.y = {
		.data = {
			0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
			0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
			0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
		}
	},
	
	.z = {
		.data = {
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		}
	},
	
	.t = {
		.data = {
			0xA3, 0xDD, 0xB7, 0xA5, 0xB3, 0x8A, 0xDE, 0x6D, 0xF5, 0x52, 0x51, 0x77,
			0x80, 0x9F, 0xF0, 0x20, 0x7D, 0xE3, 0xAB, 0x64, 0x8E, 0x4E, 0xEA, 0x66,
			0x65, 0x76, 0x8B, 0xD7, 0x0F, 0x5F, 0x87, 0x67
		}
	}
};

static const ECMScalar d = {
	.data = {
		0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75, 0xAB, 0xD8, 0x41, 0x41, 0x4D,
		0x0A, 0x70, 0x00, 0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C, 0x73, 0xFE,
		0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52
	}
};

static const ECMScalar p = {
	.data = {
		0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
	}
};

static const ECMScalar p_minus_2 = {
	.data = {
		0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
	}
};

/* Order of edwards25519 */
static const ECMScalar L = {
	.data = {
		0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2,
		0xDE, 0xF9, 0xDE, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
	}
};

static const ECMScalar two = {
	.data = {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}
};

static const ECMScalar eight = {
	.data = {
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}
};

static const ECMScalar decoding_exp = {
	.data = {
		0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F
	}
};

static const ECMScalar decoding_exp_two = {
	.data = {
		0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F
	}
};

static const ECMScalar decoding_exp_magic = {
	.data = {
		0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F
	}
};

static const ECMScalar invalid_scalar = { 0 };

#define ECM_PRINT_POINT(point) ecm_print_point(#point, point)
void ecm_print_point(const char* name, const ECMPoint point) {
	printf("%s:\n", name);
	
	printf("\tx: ");
	for (int i = 63; i >= 0; --i) printf("%02X", (point.x.data)[i]);
	printf("\n");
	
	printf("\ty: ");
	for (int i = 63; i >= 0; --i) printf("%02X", (point.y.data)[i]);
	printf("\n");
	
	printf("\tz: ");
	for (int i = 63; i >= 0; --i) printf("%02X", (point.z.data)[i]);
	printf("\n");
	
	printf("\tt: ");
	for (int i = 63; i >= 0; --i) printf("%02X", (point.t.data)[i]);
	printf("\n");

	return;
}

#define ECM_PRINT_SCALAR(scalar) ecm_print_scalar(#scalar, scalar)
void ecm_print_scalar(const char* name, const ECMScalar scalar) {
	printf("%s: ", name);
	for (int i = 63; i >= 0; --i) printf("%02X", (scalar.data)[i]);
	printf("\n");
	return;
}

static ECMTempScalar* head_scalar = NULL;
static ECMTempScalar* curr_scalar = NULL;

void ecm_clean_temp(void) {
	while (head_scalar != NULL) {
		ECMTempScalar* next_scalar = head_scalar -> next;
		KOCKET_SAFE_FREE(head_scalar);
		head_scalar = next_scalar;
	}
	curr_scalar = NULL;
	return;
}

/// TODO: Should rewrite most of the code for readability, and furthermore also for optimizations!!!
// TODO: Pass int for err handling
// TODO: Find a way to maintain the sugar syntax, while performing error
//       handling (and maybe possibly also avoid repetitive temp allocations)
ECMScalar ecm_add(ECMScalar a, ECMScalar b) {
	ECMTempScalar* temp_scalar = calloc(1, sizeof(ECMTempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}

	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;

	BigNum a_num = POS_STATIC_BIG_NUM(a.data, SCALAR_SIZE);
	BigNum b_num = POS_STATIC_BIG_NUM(b.data, SCALAR_SIZE);
	BigNum p_num = POS_STATIC_BIG_NUM(p.data, SCALAR_SIZE);
	BigNum res   = POS_STATIC_BIG_NUM((temp_scalar -> value).data, SCALAR_SIZE);

	__chonky_add(&res, &a_num, &b_num);

	ECMScalar temp_data = {0};
	BigNum temp_res = POS_STATIC_BIG_NUM(temp_data.data, SCALAR_SIZE);
	mem_cpy(temp_data.data, res.data, sizeof(ECMScalar));
	
	if (__chonky_mod_mersenne(&res, &temp_res, &p_num) == NULL) return invalid_scalar;
	
	return temp_scalar -> value;
}

ECMScalar ecm_sub(ECMScalar a, ECMScalar b) {
	ECMTempScalar* temp_scalar = calloc(1, sizeof(ECMTempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;
	
	BigNum a_num = POS_STATIC_BIG_NUM(a.data, SCALAR_SIZE);
	BigNum b_num = POS_STATIC_BIG_NUM(b.data, SCALAR_SIZE);
	BigNum p_num = POS_STATIC_BIG_NUM(p.data, SCALAR_SIZE);
	BigNum res   = POS_STATIC_BIG_NUM((temp_scalar -> value).data, SCALAR_SIZE);
	
	res.sign = !chonky_is_gte(&a_num, &b_num);
	
	__chonky_sub(&res, &a_num, &b_num);
		
	ECMScalar temp_data = {0};
	BigNum temp_res = POS_STATIC_BIG_NUM(temp_data.data, SCALAR_SIZE);
	mem_cpy(temp_data.data, res.data, sizeof(ECMScalar));
	
	if (__chonky_mod_mersenne(&res, &temp_res, &p_num) == NULL) return invalid_scalar;
	
	if (res.sign) {
		res.sign = 0;
		__chonky_sub(&res, &p_num, &res);
	}

	return temp_scalar -> value;
}

ECMScalar ecm_mul(ECMScalar a, ECMScalar b) {
	ECMTempScalar* temp_scalar = calloc(1, sizeof(ECMTempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;

	u8* temp_data[SCALAR_SIZE * 2 + 8] = {0};
	BigNum a_num   = POS_STATIC_BIG_NUM(a.data, SCALAR_SIZE);
	BigNum b_num   = POS_STATIC_BIG_NUM(b.data, SCALAR_SIZE);
	BigNum p_num   = POS_STATIC_BIG_NUM(p.data, SCALAR_SIZE);
	BigNum res     = POS_STATIC_BIG_NUM(temp_data, SCALAR_SIZE * 2 + 8);
	BigNum res_num = POS_STATIC_BIG_NUM((temp_scalar -> value).data, SCALAR_SIZE);

	if (__chonky_mul_s(&res, &a_num, &b_num) == NULL) return invalid_scalar;
	if (__chonky_mod_mersenne(&res_num, &res, &p_num) == NULL) return invalid_scalar;

	return temp_scalar -> value;
}


#define ecm_inv(scalar) ecm_spow(scalar, p_minus_2)
ECMScalar ecm_spow(ECMScalar a, ECMScalar exp) {
	ECMTempScalar* temp_scalar = calloc(1, sizeof(ECMTempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;
	
	BigNum a_num   = POS_STATIC_BIG_NUM(a.data, SCALAR_SIZE);
	BigNum p_num   = POS_STATIC_BIG_NUM(p.data, SCALAR_SIZE);
	BigNum exp_num = POS_STATIC_BIG_NUM(exp.data, SCALAR_SIZE);
	BigNum res     = POS_STATIC_BIG_NUM((temp_scalar -> value).data, SCALAR_SIZE);

	if (__chonky_pow_mod_mersenne(&res, &a_num, &exp_num, &p_num) == NULL) return invalid_scalar;

	return temp_scalar -> value;
}

ECMScalar ecm_pow(ECMScalar a, u64 exp) {
	ECMTempScalar* temp_scalar = calloc(1, sizeof(ECMTempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;

	BigNum a_num   = POS_STATIC_BIG_NUM(a.data, SCALAR_SIZE);
	BigNum p_num   = POS_STATIC_BIG_NUM(p.data, SCALAR_SIZE);
	BigNum exp_num = POS_STATIC_BIG_NUM(&exp, 8);
	BigNum res     = POS_STATIC_BIG_NUM((temp_scalar -> value).data, SCALAR_SIZE);

	if (__chonky_pow_mod_mersenne(&res, &a_num, &exp_num, &p_num) == NULL) return invalid_scalar;
	
	return temp_scalar -> value;
}

ECMScalar ptr_to_scalar(u8* ptr, u64 size) {
	ECMScalar ext_scalar = {0};
	mem_cpy(ext_scalar.data, ptr, MIN(size, sizeof(ECMScalar)));
	return ext_scalar;
}

ECMScalar ecm_mod(ECMScalar a, ECMScalar mod_base) {
	ECMTempScalar* temp_scalar = calloc(1, sizeof(ECMTempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;

	BigNum a_num        = POS_STATIC_BIG_NUM(a.data, SCALAR_SIZE);
	BigNum mod_base_num = POS_STATIC_BIG_NUM(mod_base.data, SCALAR_SIZE);
	BigNum res          = POS_STATIC_BIG_NUM(temp_scalar -> value.data, SCALAR_SIZE);

	if (__chonky_mod(&res, &a_num, &mod_base_num) == NULL) return invalid_scalar;
	
	return temp_scalar -> value;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * NOTE:                                                                 *
 * As we perform operation modulo p, also this can be reinterpreted as:  *
 * neg_a = -a (mod p) <==> neg_a = p - a                                 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ECMScalar ecm_neg(ECMScalar a) {
	ECMScalar neg_a = ecm_sub(p, a);
	/* if (err) { */
	/* 	WARNING_LOG("Failed to perform negation."); */
	/* 	return invalid_scalar; */
	/* } */
	return neg_a;
}

bool ecm_iseq(ECMScalar a, ECMScalar b) {
	for (int i = sizeof(ECMScalar) - 1; i >= 0; --i) {
		if (a.data[i] != b.data[i]) return FALSE;
	}
	return TRUE;
}

// TODO: Fix/Optimize the gt and gt_eq loops for early exit detection
bool ecm_is_gt(ECMScalar a, ECMScalar b) {
	for (int i = sizeof(ECMScalar) - 1; i >= 0; --i) {
		if (a.data[i] <= b.data[i]) return FALSE;
	}
	return TRUE;
}

/// TODO: rename to ecm_is_gte
bool ecm_is_gt_eq(ECMScalar a, ECMScalar b) {
	for (int i = sizeof(ECMScalar) - 1; i >= 0; --i) {
		if (a.data[i] < b.data[i]) return FALSE;
	}
	return TRUE;
}

bool is_point_eq(ECMPoint* a, ECMPoint* b) {
	const ECMScalar zero = {0};
	ECMScalar cond_a = ecm_sub(ecm_mul(a -> x, b -> z), ecm_mul(b -> x, a -> z));
	if (!ecm_iseq(cond_a, zero)) { 
		ecm_clean_temp();
		return FALSE;
	}

	ECMScalar cond_b = ecm_sub(ecm_mul(a -> y, b -> z), ecm_mul(b -> y, a -> z));
	if (!ecm_iseq(cond_b, zero)) {
		ecm_clean_temp();
		return FALSE;
	}

	ecm_clean_temp();

	return TRUE;
}

// TODO: Is clear that we trade between code elegance and clarity with a bit of
// memory cost (perhaps even performance overhead?), as we use temp variables
ECMPoint* add_point(ECMPoint* point_a, ECMPoint* point_b, bool same_point) {
	ECMScalar A = ecm_mul(ecm_sub(point_a -> y, point_a -> x), ecm_sub(point_b -> y, point_b -> x));
	ECMScalar B = ecm_mul(ecm_add(point_a -> y, point_a -> x), ecm_add(point_b -> y, point_b -> x));
	ECMScalar C = ecm_mul(ecm_mul(ecm_mul(point_a -> t, two), d), point_b -> t);
	ECMScalar D = ecm_mul(ecm_mul(point_a -> z, two), point_b -> z);
	ECMScalar E = ecm_sub(B, A);
	ECMScalar F = ecm_sub(D, C);
	ECMScalar G = ecm_add(D, C);
	ECMScalar H = ecm_add(B, A);

	if (same_point) {
		mem_cpy((point_a -> x).data, ecm_mul(E, F).data, sizeof(ECMScalar));
		mem_cpy((point_a -> y).data, ecm_mul(G, H).data, sizeof(ECMScalar));
		mem_cpy((point_a -> t).data, ecm_mul(E, H).data, sizeof(ECMScalar));
		mem_cpy((point_a -> z).data, ecm_mul(F, G).data, sizeof(ECMScalar));
		
		ecm_clean_temp();
		
		return point_a;
	}

	ECMPoint* point = calloc(1, sizeof(ECMPoint));
	if (point == NULL) {
		ecm_clean_temp();
		WARNING_LOG("Failed to allocate point buffer.");
		return NULL;
	}

	mem_cpy((point -> x).data, ecm_mul(E, F).data, sizeof(ECMScalar));
	mem_cpy((point -> y).data, ecm_mul(G, H).data, sizeof(ECMScalar));
	mem_cpy((point -> t).data, ecm_mul(E, H).data, sizeof(ECMScalar));
	mem_cpy((point -> z).data, ecm_mul(F, G).data, sizeof(ECMScalar));
	
	ecm_clean_temp();
	
	return point;
}

ECMPoint* double_point(ECMPoint* point, bool same_point) {
	ECMScalar A = ecm_pow(point -> x, 2);
	ECMScalar B = ecm_pow(point -> y, 2);
	ECMScalar C = ecm_mul(ecm_pow(point -> z, 2), two);
	ECMScalar H = ecm_add(A, B);
	ECMScalar E = ecm_sub(H, ecm_pow(ecm_add(point -> x, point -> y), 2));
	ECMScalar G = ecm_sub(A, B);
	ECMScalar F = ecm_add(C, G);
	
	if (same_point) {
		mem_cpy((point -> x).data, ecm_mul(E, F).data, sizeof(ECMScalar));
		mem_cpy((point -> y).data, ecm_mul(G, H).data, sizeof(ECMScalar));
		mem_cpy((point -> t).data, ecm_mul(E, H).data, sizeof(ECMScalar));
		mem_cpy((point -> z).data, ecm_mul(F, G).data, sizeof(ECMScalar));
		
		ecm_clean_temp();
		
		return point;
	}
	
	ECMPoint* res_point = calloc(1, sizeof(ECMPoint));
	if (res_point == NULL) {
		ecm_clean_temp();
		WARNING_LOG("Failed to allocate point buffer.");
		return NULL;
	}

	mem_cpy((res_point -> x).data, ecm_mul(E, F).data, sizeof(ECMScalar));
	mem_cpy((res_point -> y).data, ecm_mul(G, H).data, sizeof(ECMScalar));
	mem_cpy((res_point -> t).data, ecm_mul(E, H).data, sizeof(ECMScalar));
	mem_cpy((res_point -> z).data, ecm_mul(F, G).data, sizeof(ECMScalar));
		
	ecm_clean_temp();

	return res_point;
}

static inline ECMPoint* neutral_point(ECMPoint* point) {
	(point -> x).data[0] = 0;
	(point -> y).data[0] = 1;
	(point -> z).data[0] = 1;
	(point -> t).data[0] = 0;
	return point;
}

static ECMPoint* dup_point(ECMPoint* point) {
	ECMPoint* dup_point = calloc(1, sizeof(ECMPoint));
	if (dup_point == NULL) {
		WARNING_LOG("Failed to dup the point.");
		return NULL;
	}

	mem_cpy(dup_point -> x.data, point -> x.data, sizeof(ECMScalar));
	mem_cpy(dup_point -> y.data, point -> y.data, sizeof(ECMScalar));
	mem_cpy(dup_point -> z.data, point -> z.data, sizeof(ECMScalar));
	mem_cpy(dup_point -> t.data, point -> t.data, sizeof(ECMScalar));

	return dup_point;
}

ECMPoint* mul_point(ECMScalar scalar, ECMPoint* P, ECMPoint* R) {
	ECMPoint* base_mul_point = dup_point(P);
	neutral_point(R);
	
	for (unsigned int i = 0; i < 255; ++i) {
    	if (GET_SCALAR_BIT(scalar, i)) add_point(R, base_mul_point, TRUE);
		double_point(base_mul_point, TRUE);
	}
	
	KOCKET_SAFE_FREE(base_mul_point);
	
	return R;
}

void compress_point(ECMScalar* res, ECMPoint* point) {
	ECMScalar z_inv = ecm_inv(point -> z);
	ECMScalar x = ecm_mul(point -> x, z_inv);
	ECMScalar y = ecm_mul(point -> y, z_inv);

	mem_cpy(res -> data, y.data, sizeof(ECMScalar));
	(res -> data)[31] |= (x.data[0] & 0x01) << 7;
	
	ecm_clean_temp();
	
	return;
}

// TODO: Maybe should rewrite the squaring powers into simple "a*a" multiplications
ECMPoint* decode_point(ECMScalar scalar, ECMPoint* point) {
	ECMScalar y = {0};
	mem_cpy(y.data, scalar.data, LITTLE_SCALAR_SIZE);
	KOCKET_BE_CONVERT(y.data, LITTLE_SCALAR_SIZE);
	
	u8 sign = GET_SCALAR_BIT(y, 31 * 8 + 7);
	y.data[31] &= ~(0x80);

	if (ecm_is_gt(y, p)) {
		WARNING_LOG("Failed to decode point, as the y-coordinate is greather than the field prime modulo p.");
		return NULL;
	}

	ECMScalar u = ecm_sub(ecm_pow(y, 2), base_point.z);
	ECMScalar v = ecm_add(ecm_mul(d, ecm_pow(y, 2)), base_point.z);
	ECMScalar x2 = ecm_mul(u, ecm_inv(v));

	const ECMScalar zero = {0};
	if (ecm_iseq(x2, zero) && sign) {
		ecm_clean_temp();
		WARNING_LOG("Failed to decode point, as x2 cannot be zero.");
		return NULL;
	}

	ECMScalar x = ecm_spow(x2, decoding_exp_magic);

	if (!ecm_iseq(ecm_sub(ecm_pow(x, 2), x2), zero)) {
		// Set x <-- x * 2^((p-1)/4), which is a square root.
		x = ecm_mul(x, ecm_spow(two, decoding_exp_two));
	} 

	if (!ecm_iseq(ecm_sub(ecm_pow(x, 2), x2), zero)) {
		// No square root exists for modulo p
		ecm_clean_temp();
		WARNING_LOG("Failed to decode point, as no square root exists for modulo p.");
		return NULL;
	}
	
	if (GET_SCALAR_BIT(x, 0) != sign) {
		// Otherwise, if sign != x mod 2, set x <-- p - x.  
		x = ecm_sub(p, x);
	}

	mem_cpy((point -> x).data, x.data,   sizeof(ECMScalar));
	mem_cpy((point -> y).data, y.data,   sizeof(ECMScalar));
	(point -> z).data[0] = 1;
	mem_cpy((point -> t).data, ecm_mul(point -> x, point -> y).data, sizeof(ECMScalar));

	// Clean only after copying as x and y are temp scalars
	ecm_clean_temp();

	return point;
}

#endif //_ECM_OPS_H_

