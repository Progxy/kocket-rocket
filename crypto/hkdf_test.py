import hashlib
import hmac

def hkdf_extract(salt: bytes, ikm: bytes, hash_fn=hashlib.sha256) -> bytes:
    """
    HKDF-Extract(salt, IKM) -> PRK
    """
    if salt is None: salt = b"\x00" * hash_fn().digest_size
    
    return hmac.new(salt, ikm, hash_fn).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int, hash_fn=hashlib.sha256) -> bytes:
    """
    HKDF-Expand(PRK, info, L) -> OKM
    """
    hash_len = hash_fn().digest_size
    if length > 255 * hash_len:
        raise ValueError("Requested key length too long")

    okm = b""
    t = b""
    counter = 1

    while len(okm) < length:
        concat = t + info + bytes([counter])
        t = hmac.new(prk, concat, hash_fn).digest()
        okm += t
        counter += 1
        print(f"prk: {prk.hex().upper()}\nconcat: {concat.hex().upper()}\nt: {t.hex().upper()}\nokm: {okm.hex().upper()}")

    return okm[:length]

def hkdf(ikm: bytes, length: int, salt: bytes = None, info: bytes = b"", hash_fn=hashlib.sha256) -> bytes:
    prk = hkdf_extract(salt, ikm, hash_fn)
    print(f"prk: {prk.hex().upper()}")
    return hkdf_expand(prk, info, length, hash_fn)

if __name__ == "__main__":
    sender_ed25519_pub = bytes.fromhex("8889396F8BFB39AAB5FAC76DD850A1C57FC8AA99CDF809B0C2730DAA1DFC2026")
    recipient_x25519_pub = bytes.fromhex("3DC70812B40C32E9405613950A5C51CFC2142E16375A71672FE87A6E13E6CA66")
    shared_secret = bytes.fromhex("70B1F7C87187303C8875F58A09136326AD5DAFE7137D60B1B411D15638188542")
    sequence_number = 1

    info = (
        b"X25519-CHACHA20POLY1305-v1" +
        sender_ed25519_pub +
        recipient_x25519_pub +
        sequence_number.to_bytes(8, "little")
    )

    print(f"info: {info.hex().upper()}")

    key_material = hkdf(
        ikm=shared_secret,
        length=44,   # 32-byte key + 12-byte nonce
        salt=None,
        info=info,
        hash_fn=hashlib.sha512
    )

    aead_key = key_material[:32]
    aead_nonce = key_material[32:44]

    print(f"aead_key: {aead_key.hex().upper()}\naead_nonce: {aead_nonce.hex().upper()}")
