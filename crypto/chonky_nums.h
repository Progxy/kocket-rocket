#ifndef _CHONKY_NUMS_H_
#define _CHONKY_NUMS_H_

#define MIN(a, b) ((a) >= (b) ? (b) : (a))
#define GET_SCALAR_BIT(val, n) ((((val).data[(((n) - ((n) % 8)) / 8)]) >> ((n) % 8)) & 0x01)

typedef struct {
	u8 data[64];
} Ed25519Scalar;

typedef struct Ed25519Coord {
	Ed25519Scalar x;
	Ed25519Scalar y;
} Ed25519Coord;

typedef struct Ed25519Point {
	Ed25519Scalar x;
	Ed25519Scalar y;
	Ed25519Scalar z;
	Ed25519Scalar t;
} Ed25519Point;

typedef struct Ed25519TempScalar {
	Ed25519Scalar value;
	struct Ed25519TempScalar* next;
} Ed25519TempScalar;

/* NOTE:
 * A point (x,y) is represented in extended homogeneous coordinates 
 * (X, Y, Z, T), with x = X/Z, y = Y/Z, x * y = T/Z. 
 * The neutral point is (0,1), or equivalently in extended homogeneous 
 * coordinates (0, Z, Z, 0) for any non-zero Z.
*/

static const Ed25519Point base_point = { 
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

static const Ed25519Scalar d = {
	.data = {
		0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75, 0xAB, 0xD8, 0x41, 0x41, 0x4D,
		0x0A, 0x70, 0x00, 0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C, 0x73, 0xFE,
		0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52
	}
};

static const Ed25519Scalar p = {
	.data = {
		0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
	}
};

/* Order of edwards25519 */
static const Ed25519Scalar L = {
	.data = {
		0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2,
		0xDE, 0xF9, 0xDE, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
	}
};

static const Ed25519Scalar two = {
	.data = {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}
};

static const Ed25519Scalar eight = {
	.data = {
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}
};

static const Ed25519Scalar decoding_exp = {
	.data = {
		0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F
	}
};

static const Ed25519Scalar decoding_exp_two = {
	.data = {
		0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F
	}
};

static const Ed25519Scalar invalid_scalar = { 0 };

static Ed25519TempScalar* head_scalar = NULL;
static Ed25519TempScalar* curr_scalar = NULL;

/* NOTE: Unless explicitly said each operation is performed modulo p */

void ed25519_clean_temp(void) {
	while (head_scalar != NULL) {
		Ed25519TempScalar* prev_scalar = head_scalar;
		KOCKET_SAFE_FREE(prev_scalar);
		head_scalar = head_scalar -> next;
	}
	curr_scalar = NULL;
	return;
}

// TODO: Pass int for err handling
Ed25519Scalar ed25519_add(Ed25519Scalar a, Ed25519Scalar b) {
	Ed25519TempScalar* temp_scalar = calloc(1, sizeof(Ed25519TempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;

	TODO("Implement me!");
	return temp_scalar -> value;
}

Ed25519Scalar ed25519_sub(Ed25519Scalar a, Ed25519Scalar b) {
	Ed25519TempScalar* temp_scalar = calloc(1, sizeof(Ed25519TempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;

	TODO("Implement me!");
	return temp_scalar -> value;
}

Ed25519Scalar ed25519_mul(Ed25519Scalar a, Ed25519Scalar b) {
	Ed25519TempScalar* temp_scalar = calloc(1, sizeof(Ed25519TempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;

	TODO("Implement me!");
	return temp_scalar -> value;
}

Ed25519Scalar ed25519_div(Ed25519Scalar a, Ed25519Scalar b) {
	Ed25519TempScalar* temp_scalar = calloc(1, sizeof(Ed25519TempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;

	TODO("Implement me!");
	return temp_scalar -> value;
}

Ed25519Scalar ed25519_pow(Ed25519Scalar a, u64 exp) {
	Ed25519TempScalar* temp_scalar = calloc(1, sizeof(Ed25519TempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;

	TODO("Implement me!");
	return temp_scalar -> value;
}

Ed25519Scalar ed25519_spow(Ed25519Scalar a, Ed25519Scalar exp) {
	Ed25519TempScalar* temp_scalar = calloc(1, sizeof(Ed25519TempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;

	TODO("Implement me!");
	return temp_scalar -> value;
}

Ed25519Scalar ptr_to_scalar(u8* ptr, u64 size) {
	Ed25519Scalar ext_scalar = {0};
	mem_cpy(ext_scalar.data, ptr, MIN(size, sizeof(Ed25519Scalar)));
	return ext_scalar;
}

Ed25519Scalar ed25519_mod(Ed25519Scalar a, Ed25519Scalar exp) {
	Ed25519TempScalar* temp_scalar = calloc(1, sizeof(Ed25519TempScalar));
	if (temp_scalar == NULL) {
		WARNING_LOG("Failed to allocate scalar buffer.");
		return invalid_scalar;
	}
	
	// Update linked list of temps
	if (head_scalar == NULL) head_scalar = temp_scalar;
	else curr_scalar -> next = temp_scalar;

	curr_scalar = temp_scalar;

	TODO("Implement me!");
	return temp_scalar -> value;
}

/* NOTE: 
 * As we perform operation modulo p, also this can be reinterpreted as:
 * neg_a = -a (mod p) <==> neg_a = p - a 
 */
Ed25519Scalar ed25519_neg(Ed25519Scalar a) {
	Ed25519Scalar neg_a = ed25519_sub(p, a);
	/* if (err) { */
	/* 	WARNING_LOG("Failed to perform negation."); */
	/* 	return invalid_scalar; */
	/* } */
	return neg_a;
}

bool ed25519_iseq(Ed25519Scalar a, Ed25519Scalar b) {
	TODO("Implement me!");
	return FALSE;
}

bool ed25519_is_gt(Ed25519Scalar a, Ed25519Scalar b) {
	TODO("Implement me!");
	return FALSE;
}

bool ed25519_is_gt_eq(Ed25519Scalar a, Ed25519Scalar b) {
	TODO("Implement me!");
	return FALSE;
}

bool is_point_eq(Ed25519Point* a, Ed25519Point* b) {
	TODO("Implement me!");
	return FALSE;
}

Ed25519Point* coord_to_point(Ed25519Coord* coord) {
	Ed25519Point* point = calloc(1, sizeof(Ed25519Point));
	if (point == NULL) {
		WARNING_LOG("Failed to allocate neutral point buffer.");
		return NULL;
	}

	mem_cpy((point -> x).data, (coord -> x).data, sizeof(Ed25519Scalar));
	mem_cpy((point -> y).data, (coord -> y).data, sizeof(Ed25519Scalar));
	(point -> z).data[0] = 1;
	mem_cpy((point -> t).data, ed25519_mul(coord -> x, coord -> y).data, sizeof(Ed25519Scalar));
	
	ed25519_clean_temp();

	return point;
}

// TODO: Is clear that we trade between code elegance and clarity with a bit of
// memory cost (perhaps even performance overhead?), as we use temp variables
Ed25519Point* add_point(Ed25519Point* point_a, Ed25519Point* point_b, bool same_point) {
	Ed25519Scalar A = ed25519_mul(ed25519_sub(point_a -> y, point_a -> x), ed25519_sub(point_b -> y, point_b -> x));
	Ed25519Scalar B = ed25519_mul(ed25519_add(point_a -> y, point_a -> x), ed25519_add(point_b -> y, point_b -> x));
	Ed25519Scalar C = ed25519_mul(ed25519_mul(ed25519_mul(point_a -> t, two), d), point_b -> t);
	Ed25519Scalar D = ed25519_mul(ed25519_mul(point_a -> z, two), point_b -> z);
	Ed25519Scalar E = ed25519_sub(B, A);
	Ed25519Scalar F = ed25519_sub(D, C);
	Ed25519Scalar G = ed25519_add(D, C);
	Ed25519Scalar H = ed25519_add(B, A);

	if (same_point) {
		mem_cpy(point_a -> x.data, ed25519_mul(E, F).data, sizeof(Ed25519Scalar));
		mem_cpy(point_a -> y.data, ed25519_mul(G, H).data, sizeof(Ed25519Scalar));
		mem_cpy(point_a -> t.data, ed25519_mul(E, H).data, sizeof(Ed25519Scalar));
		mem_cpy(point_a -> z.data, ed25519_mul(F, G).data, sizeof(Ed25519Scalar));
		
		ed25519_clean_temp();
		
		return point_a;
	}

	Ed25519Point* point = calloc(1, sizeof(Ed25519Point));
	if (point == NULL) {
		ed25519_clean_temp();
		WARNING_LOG("Failed to allocate point buffer.");
		return NULL;
	}

	mem_cpy(point -> x.data, ed25519_mul(E, F).data, sizeof(Ed25519Scalar));
	mem_cpy(point -> y.data, ed25519_mul(G, H).data, sizeof(Ed25519Scalar));
	mem_cpy(point -> t.data, ed25519_mul(E, H).data, sizeof(Ed25519Scalar));
	mem_cpy(point -> z.data, ed25519_mul(F, G).data, sizeof(Ed25519Scalar));
	
	ed25519_clean_temp();
	
	return point;
}

Ed25519Point* double_point(Ed25519Point* point, bool same_point) {
	Ed25519Scalar A = ed25519_pow(point -> x, 2);
	Ed25519Scalar B = ed25519_pow(point -> y, 2);
	Ed25519Scalar C = ed25519_mul(ed25519_pow(point -> z, 2), two);
	Ed25519Scalar H = ed25519_add(A, B);
	Ed25519Scalar E = ed25519_sub(H, ed25519_pow(ed25519_add(point -> x, point -> y), 2));
	Ed25519Scalar G = ed25519_sub(A, B);
	Ed25519Scalar F = ed25519_add(C, G);
	
	if (same_point) {
		mem_cpy(point -> x.data, ed25519_mul(E, F).data, sizeof(Ed25519Scalar));
		mem_cpy(point -> y.data, ed25519_mul(G, H).data, sizeof(Ed25519Scalar));
		mem_cpy(point -> t.data, ed25519_mul(E, H).data, sizeof(Ed25519Scalar));
		mem_cpy(point -> z.data, ed25519_mul(F, G).data, sizeof(Ed25519Scalar));
		
		ed25519_clean_temp();
	}
	
	Ed25519Point* res_point = calloc(1, sizeof(Ed25519Point));
	if (res_point == NULL) {
		ed25519_clean_temp();
		WARNING_LOG("Failed to allocate point buffer.");
		return NULL;
	}

	mem_cpy(res_point -> x.data, ed25519_mul(E, F).data, sizeof(Ed25519Scalar));
	mem_cpy(res_point -> y.data, ed25519_mul(G, H).data, sizeof(Ed25519Scalar));
	mem_cpy(res_point -> t.data, ed25519_mul(E, H).data, sizeof(Ed25519Scalar));
	mem_cpy(res_point -> z.data, ed25519_mul(F, G).data, sizeof(Ed25519Scalar));
		
	ed25519_clean_temp();

	return res_point;
}

Ed25519Point* neutral_point(void) {
	Ed25519Point* point = calloc(1, sizeof(Ed25519Point));
	if (point == NULL) {
		WARNING_LOG("Failed to allocate neutral point buffer.");
		return NULL;
	}

	(point -> x).data[0] = 0;
	(point -> y).data[0] = 1;
	(point -> z).data[0] = 1;
	(point -> t).data[0] = 0;
	
	return point;
}

Ed25519Point* mul_point(Ed25519Scalar scalar, Ed25519Point* P) {
	Ed25519Point* R = neutral_point(); 	
	for (int i = 254; i >= 0; --i) {
    	R = double_point(R, TRUE);
    	if (GET_SCALAR_BIT(scalar, i)) R = add_point(R, P, TRUE);
	}
	return R;
}

void compress_point(Ed25519Scalar res, Ed25519Point* point, bool clean) {
	Ed25519Scalar x = point -> x;
	Ed25519Scalar y = point -> y;
	
	y.data[31] &= ~(0x80);
	mem_cpy(res.data, y.data, sizeof(Ed25519Scalar));
	res.data[31] &= ~((x.data[0] & 0x01) << 7);

	if (clean) KOCKET_SAFE_FREE(point);

	return;
}

Ed25519Coord* decode_point(Ed25519Scalar scalar) {
	Ed25519Scalar x_0 = {0};
	x_0.data[0] = GET_SCALAR_BIT(scalar, 31 * 8 + 7);
	
	Ed25519Scalar y = {0};
	mem_cpy(y.data, scalar.data, sizeof(Ed25519Scalar));
	y.data[31] &= ~(0x80);

	if (ed25519_is_gt(y, p)) {
		WARNING_LOG("Failed to decode point, as the y-coordinate is greather than the field prime modulo p.");
		return NULL;
	}

	Ed25519Scalar u = ed25519_sub(ed25519_pow(y, 2), base_point.z);
	Ed25519Scalar v = ed25519_add(ed25519_mul(d, ed25519_pow(y, 2)), base_point.z);
	
	// TODO: recover x
	Ed25519Scalar x = ed25519_mul(ed25519_mul(u, (ed25519_pow(v, 3))), ed25519_spow(ed25519_mul(u, ed25519_pow(v, 7)), decoding_exp));

	if (ed25519_iseq(ed25519_mul(v, ed25519_pow(x, 2)), ed25519_neg(u))) {
		// Set x <-- x * 2^((p-1)/4), which is a square root.
		x = ed25519_mul(x, ed25519_spow(two, decoding_exp_two));
	} else if (!ed25519_iseq(ed25519_mul(v, ed25519_pow(x, 2)), u)) {
		// No square root exists for modulo p
		ed25519_clean_temp();
		WARNING_LOG("Failed to decode point, as no square root exists for modulo p.");
		return NULL;
	}

	const Ed25519Scalar zero = {0};
	if (ed25519_iseq(x, zero) && x_0.data[0] == 1) {
	    // If x = 0, and x_0 = 1, decoding fails.  
		ed25519_clean_temp();
		WARNING_LOG("Failed to decode point, x = 0, and x_0 = 1.");
		return NULL;
	} else if (!ed25519_iseq(ed25519_mod(x, two), x_0)) {
		// Otherwise, if x_0 != x mod 2, set x <-- p - x.  
		x = ed25519_sub(x, p);
	}
	
	Ed25519Coord* coord = calloc(1, sizeof(Ed25519Coord));
	if (coord == NULL) {
		ed25519_clean_temp();
		WARNING_LOG("Failed to allocate coord buffer.");
		return NULL;
	}

	mem_cpy(coord -> x.data, x.data, sizeof(Ed25519Scalar));
	mem_cpy(coord -> y.data, y.data, sizeof(Ed25519Scalar));

	// Clean only after copying as x and y are temp scalars
	ed25519_clean_temp();

	return coord;
}

#endif //_CHONKY_NUMS_H_

