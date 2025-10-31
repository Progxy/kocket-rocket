#ifndef _CHONKY_NUMS_H_
#define _CHONKY_NUMS_H_

typedef struct Number {
	u8* data;
	u64 size;
} Number;

Number chonky_add(Number a, Number b) {
	return c;
}

Number chonky_sub(Number a, Number b) {
	return c;
}

Number chonky_mul(Number a, Number b) {
	return c;
}

Number chonky_div(Number a, Number b) {
	return c;
}

/* void point_compress() { */
	/* Ed25519Coord y_encoding = encode_y(sb); */
	/* Ed25519Coord x_encoding = encode_x(sb); */
	
	/* y_encoding[31] &= ~(0x80); */
	/* mem_cpy(pub_key, y_encoding, sizeof(Ed25519Key)); */
	/* pub_key[31] &= ~((x_encoding[0] & 0x01) << 7); */
/* } */

#endif //_CHONKY_NUMS_H_

