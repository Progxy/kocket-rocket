def decodeLittleEndian(b, bits):
    return sum([b[i] << 8 * i for i in range((bits + 7) / 8)])

def decodeUCoordinate(u, bits):
   u_list = [ord(b) for b in u]
   # Ignore any unused bits.
   if bits % 8:
       u_list[-1] &= (1 << (bits % 8)) - 1
   return decodeLittleEndian(u_list, bits)

def encodeUCoordinate(u, bits):
   u = u % p
   return ''.join([chr((u >> 8 * i) & 0xFF) for i in range((bits + 7) / 8)])

def decodeScalar25519(k):
   k_list = [ord(b) for b in k]
   k_list[0] &= 248
   k_list[31] &= 127
   k_list[31] |= 64
   return decodeLittleEndian(k_list, 255)

# Field prime for Curve25519
p = 2**255 - 19

# a24 constant from RFC 7748
a24 = 121665

def cswap(swap, x, y):
    """
    Constant-time conditional swap.
    swap must be 0 or 1.
    """
    mask = -swap & ((1 << 256) - 1)  # full mask of all bits
    xr = x ^ y
    xr &= mask
    return x ^ xr, y ^ xr

def x25519_ladder(k, u, bits=255):
    x1 = u
    x2 = 1
    z2 = 0
    x3 = u
    z3 = 1
    swap = 0

    for t in reversed(range(bits + 1)):  # bits-1 down to 0
        kt = (k >> t) & 1
        swap ^= kt

        # Conditional swap
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)

        swap = kt

        # Curve25519 Montgomery ladder formulas
        A = (x2 + z2) % p
        AA = (A * A) % p
        B = (x2 - z2) % p
        BB = (B * B) % p
        E = (AA - BB) % p

        C = (x3 + z3) % p
        D = (x3 - z3) % p
        DA = (D * A) % p
        CB = (C * B) % p

        x3 = ((DA + CB)**2) % p
        z3 = (x1 * ((DA - CB)**2 % p)) % p
        x2 = (AA * BB) % p
        z2 = (E * ((AA + a24 * E) % p)) % p

    # Final swap
    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)

    # Return x2 * z2^(p-2)  (field inversion)
    return (x2 * pow(z2, p - 2, p)) % p

if __name__ == "__main__":
    print("Hi")

