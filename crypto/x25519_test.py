import sys
import random

# Field prime for Curve25519
P = 2**255 - 19

# a24 constant from RFC 7748
A24 = 121665

BASEPOINT = (9).to_bytes(32, "little")

def random_32_bytes():
    return bytes(random.getrandbits(8) for _ in range(32))

def to_hex(label, b):
    if type(b) == int: print(f"{label}: {b:X}")
    else: print(f"{label}: {b.hex().upper()}")

def clamp_scalar(k: bytes) -> bytes:
    k = bytearray(k)
    k[0]  &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)

def decode_scalar25519(k: bytes) -> int:
    assert len(k) == 32
    k = bytearray(k)

    # RFC 7748 clamping
    k[0]  &= 248
    k[31] &= 127
    k[31] |= 64

    return int.from_bytes(k, "little")

def decode_u_coordinate(u: bytes) -> int:
    assert len(u) == 32
    return int.from_bytes(u, "little") % P

def encode_u_coordinate(u: int) -> bytes:
    return (u % P).to_bytes(32, "little")

def cswap(swap: int, x2: int, x3: int):
    mask = -swap
    t = mask & (x2 ^ x3)
    x2 ^= t
    x3 ^= t
    return x2, x3

def x25519(scalar_bytes: bytes, u_bytes: bytes) -> bytes:
    # Decode inputs
    k = decode_scalar25519(scalar_bytes)
    u = decode_u_coordinate(u_bytes)
    
    # Initialize
    x1 = u
    x2 = 1
    z2 = 0
    x3 = u
    z3 = 1
    swap = 0

    # Montgomery ladder
    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t

        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = k_t

        A  = (x2 + z2) % P
        AA = (A * A) % P
        B  = (x2 - z2) % P
        BB = (B * B) % P
        E  = (AA - BB) % P
        C  = (x3 + z3) % P
        D  = (x3 - z3) % P
        DA = (D * A) % P
        CB = (C * B) % P

        x3 = ((DA + CB) ** 2) % P
        z3 = (x1 * ((DA - CB) ** 2 % P)) % P
        x2 = (AA * BB) % P
        z2 = (E * (AA + A24 * E % P)) % P

    # Final swap
    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)

    # Affine conversion: x2 / z2
    result = (x2 * pow(z2, P - 2, P)) % P

    return encode_u_coordinate(result)

if __name__ == "__main__":
    # Recipient static private key
    recipient_priv_raw = bytes.fromhex("60EB4BCE379A0217D8888AB278F61A90A2C481B63745F47B25620B8EA2DBD358")
    recipient_priv = clamp_scalar(recipient_priv_raw)

    # Recipient public key
    recipient_pub = x25519(recipient_priv, BASEPOINT)

    print("=== Recipient static keypair ===")
    to_hex("recipient_priv", recipient_priv)
    to_hex("recipient_pub ", recipient_pub)
    print()
    
    # Sender ephemeral private key
    sender_eph_priv_raw = bytes.fromhex("7BECEC1BEE8412B5D4F101B83839F7B6FA7E3E03291EB8197C3A709429A87F80")
    sender_eph_priv = clamp_scalar(sender_eph_priv_raw)

    # Sender ephemeral public key
    sender_eph_pub = x25519(sender_eph_priv, BASEPOINT)

    print("=== Sender ephemeral keypair ===")
    to_hex("sender_eph_priv", sender_eph_priv)
    to_hex("sender_eph_pub ", sender_eph_pub)
    print()

    sender_shared = x25519(sender_eph_priv, recipient_pub)

    print("=== Sender computed shared secret ===")
    to_hex("sender_shared", sender_shared)
    print()

    recipient_shared = x25519(recipient_priv, sender_eph_pub)

    print("=== Recipient computed shared secret ===")
    to_hex("recipient_shared", recipient_shared)
    print()

    print("=== Equality check ===")
    print("Shared secrets match:", sender_shared == recipient_shared)

