import hashlib

def sha512_single_pass(msg: bytes) -> bytes:
    h = hashlib.sha512()
    h.update(msg)
    return h.digest()

def sha512_multi_update(msg: bytes, splits) -> bytes:
    """
    splits: iterable of chunk sizes
    """
    h = hashlib.sha512()
    offset = 0
    for s in splits:
        msg_split = msg[offset:offset + s]
        h.update(msg_split)
        offset += s
    assert offset == len(msg)
    return h.digest()

if __name__ == "__main__":
    msg = bytes(range(256)) * 3  # 768 bytes, non-uniform data
    splits = [127, 2, 1, 128, 17, 300, 193]

    ref = sha512_single_pass(msg)
    out = sha512_multi_update(msg, splits)

    assert out == ref

    print(f"out: {out.hex().upper()}\nref: {ref.hex().upper()}")
