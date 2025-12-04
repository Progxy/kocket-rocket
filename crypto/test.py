## First, some preliminaries that will be needed.
import hashlib
import sys

def sha512(s):
    return hashlib.sha512(s).digest()

# Base field Z_p
p = 2**255 - 19

def modp_inv(x):
    return pow(x, p-2, p)

# Curve constant
d = -121665 * modp_inv(121666) % p

# Group order
q = 2**252 + 27742317777372353535851937790883648493

def sha512_modq(s):
    return int.from_bytes(sha512(s), "little") % q

## Then follows functions to perform point operations.

# Points are represented as tuples (X, Y, Z, T) of extended
# coordinates, with x = X/Z, y = Y/Z, x*y = T/Z

def double_point(P):
    A = P[0] ** 2 % p
    B = P[1] ** 2 % p
    C = 2 * P[2] ** 2 % p
    

    H = (A + B) % p
    E = (H - (P[0] + P[1]) ** 2) % p
    
    G = (A - B) % p
    F = (C + G) % p
    
    x_3 = E * F
    print(f"x3 = {x_3:X}")
    x_3 %= p
    print(f"_x3 = {x_3:X}\n")
    
    res = [E * F, G * H, F * G, E * H]
    for i in range(0, 4): res[i] %= p 
    
    return res

def point_add(P, Q):
    A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % p, (P[1] + P[0]) * (Q[1] + Q[0]) % p;
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p;
    E, F, G, H = B - A, D - C, D + C, B + A;
    return (E * F, G * H, F * G, E * H);

# Computes Q = s * Q
def point_mul(s, P):
    Q = (0, 1, 1, 0)  # Neutral element
    count = 0
    while s > 0:
        print(f"----------------------")
        for i, elem in enumerate(Q): print(f"#Q_{count}_{i}: {elem:X}")
        print("")
        if s & 1:
            Q = point_add(Q, P)
        for i, elem in enumerate(Q): print(f"__Q_{count}_{i}: {elem:X}")
        print("")
        for i, elem in enumerate(P): print(f"#P_{count}_{i}: {elem:X}")
        print("")
        T_P = P
        P = point_add(P, P)
        for i, elem in enumerate(P): print(f"__P_{count}_{i}: {elem:X}")
        print("")
        T_P = double_point(T_P)
        for i, elem in enumerate(T_P): print(f"__T_P_{count}_{i}: {elem:X}")
        print(f"----------------------\n")
        s >>= 1
        if count == 0: sys.exit(1)
        count += 1
    return Q

def point_equal(P, Q):
    # x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True

## Now follows functions for point compression.

# Square root of -1
modp_sqrt_m1 = pow(2, (p-1) // 4, p)

# Compute corresponding x-coordinate, with low bit corresponding to
# sign, or return None on failure
def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y*y-1) * modp_inv(d*y*y+1)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0

    # Compute square root of x2
    x = pow(x2, (p+3) // 8, p)
    if (x*x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x*x - x2) % p != 0:
        return None

    if (x & 1) != sign:
        x = p - x
    return x

# Base point
g_y = 4 * modp_inv(5) % p
g_x = recover_x(g_y, 0)
G = (g_x, g_y, 1, g_x * g_y % p)

def point_compress(P):
    zinv = modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")

def point_decompress(s):
    if len(s) != 32:
        raise Exception("Invalid input length for decompression")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return (x, y, 1, x*y % p)

## These are functions for manipulating the private key.

def secret_expand(secret):
    if len(secret) != 32:
        raise Exception("Bad size of private key")
    h = sha512(secret)
    a = int.from_bytes(h[:32], "little")
    print(f"h:{h.hex()}\na: {h[:32].hex()}\na: {a:X}")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    print(f"a: {a:X}")
    return (a, h[32:])

def secret_to_public(secret):
    (a, dummy) = secret_expand(secret)
    for i, elem in enumerate(G): print(f"G_{i}: {elem:X}")
    ml = point_mul(a, G)
    for i, elem in enumerate(ml): print(f"ml_{i}: {elem:X}")
    return point_compress(ml)

## The signature function works as below.
def sign(secret, msg):
    a, prefix = secret_expand(secret)
    A = point_compress(point_mul(a, G))
    r = sha512_modq(prefix + msg)
    print(f"r: {r:X}")
    R = point_mul(r, G)
    Rs = point_compress(R)
    h = sha512_modq(Rs + A + msg)
    s = (r + h * a) % q
    return Rs + int.to_bytes(s, 32, "little")

## And finally the verification function.

def verify(public, msg, signature):
    if len(public) != 32:
        raise Exception("Bad public key length")
    if len(signature) != 64:
        Exception("Bad signature length")
    A = point_decompress(public)
    if not A:
        return False
    Rs = signature[:32]
    R = point_decompress(Rs)
    if not R:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= q: return False
    h = sha512_modq(Rs + public + msg)
    sB = point_mul(s, G)
    hA = point_mul(h, A)
    return point_equal(sB, point_add(R, hA))

if __name__ == "__main__":
    priv_key = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub_key = secret_to_public(priv_key)
    print(f"public: {pub_key.hex()}")
    # signature = sign(priv_key, b"")
    # print(f"signature: {signature.hex()}")


