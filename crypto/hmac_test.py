import hashlib

def hmac_generic(key: bytes, message: bytes, hash_func):
    """
    Pure Python HMAC implementation (RFC 2104).

    :param key: secret key (bytes)
    :param message: message to authenticate (bytes)
    :param hash_func: function that takes bytes and returns bytes (digest)
    :param block_size: block size of the hash function (e.g., 64 for SHA-256)
    :return: HMAC digest (bytes)
    """
    block_size = hash_func().block_size  # SHA-256 block size

    # Step 1: If key is longer than block size, hash it
    if len(key) > block_size: 
        key = hash_func(key).digest()

    # Step 2: Pad key to block size with zeros
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))

    # Step 3: Create inner and outer padded keys
    ipad = bytes((k ^ 0x36) for k in key)
    opad = bytes((k ^ 0x5c) for k in key)

    print(f"ipad: {ipad.hex().upper()}\nopad: {opad.hex().upper()}")

    print(f"spms(len: {len(ipad + message)}): {(ipad + message).hex().upper()}")

    # Step 4: Inner hash
    inner_hash = hash_func(ipad + message).digest()

    print(f"inner_hash: {inner_hash.hex().upper()}")

    # Step 5: Outer hash
    return hash_func(opad + inner_hash).digest()

if __name__ == "__main__":
    hash_fn = hashlib.sha512
    key = bytes.fromhex("70B1F7C87187303C8875F58A09136326AD5DAFE7137D60B1B411D15638188542")
    message = b"\x00" * hash_fn().digest_size

    mac = hmac_generic(
        key = message,
        message = key, 
        hash_func = hash_fn
    )

    print(mac.hex())

