from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
import time

_STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_ALT_ALPHABET = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP="
_ENC_TABLE = str.maketrans(_STD_ALPHABET, _ALT_ALPHABET)
_DEC_TABLE = str.maketrans(_ALT_ALPHABET, _STD_ALPHABET)


class ChaCha20:
    CONST = [1196819126, 600974999, 3863347763, 1451689750]

    def __init__(self, key_words: list[int]) -> None:
        if len(key_words) != 12:
            raise ValueError("buffer underflow")
        self.key_words = list(key_words)
        self.rounds = self._calc_rounds(key_words)
        self.state = self.CONST + self.key_words

    @staticmethod
    def _u32(x: int) -> int:
        return x & 0xFFFFFFFF

    @staticmethod
    def _rotl(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _calc_rounds(key_words: list[int]) -> int:
        acc = sum(w & 0xF for w in key_words) & 0xF
        return acc + 5

    @classmethod
    def _quarter(cls, s: list[int], a: int, b: int, c: int, d: int) -> None:
        s[a] = cls._u32(s[a] + s[b])
        s[d] = cls._rotl(s[d] ^ s[a], 16)
        s[c] = cls._u32(s[c] + s[d])
        s[b] = cls._rotl(s[b] ^ s[c], 12)
        s[a] = cls._u32(s[a] + s[b])
        s[d] = cls._rotl(s[d] ^ s[a], 8)
        s[c] = cls._u32(s[c] + s[d])
        s[b] = cls._rotl(s[b] ^ s[c], 7)

    @classmethod
    def _block(cls, state: list[int], rounds: int) -> list[int]:
        w = state.copy()
        r = 0
        while r < rounds:
            cls._quarter(w, 0, 4, 8, 12)
            cls._quarter(w, 1, 5, 9, 13)
            cls._quarter(w, 2, 6, 10, 14)
            cls._quarter(w, 3, 7, 11, 15)
            r += 1
            if r >= rounds:
                break
            cls._quarter(w, 0, 5, 10, 15)
            cls._quarter(w, 1, 6, 11, 12)
            cls._quarter(w, 2, 7, 12, 13)
            cls._quarter(w, 3, 4, 13, 14)
            r += 1
        for i in range(16):
            w[i] = cls._u32(w[i] + state[i])
        return w

    def encrypt(self, data: bytes) -> bytes:
        buf = list(data)
        self._crypt_inplace(self.state, self.rounds, buf)
        return bytes(buf)

    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)

    @classmethod
    def _crypt_inplace(cls, state_16: list[int], rounds: int, data: list[int]) -> None:
        n_full = len(data) // 4
        leftover = len(data) % 4
        words = [0] * ((len(data) + 3) // 4)

        for i in range(n_full):
            j = 4 * i
            words[i] = data[j] | (data[j + 1] << 8) | (data[j + 2] << 16) | (data[j + 3] << 24)
        if leftover:
            for c in range(leftover):
                words[n_full] |= data[4 * n_full + c] << (8 * c)

        state = state_16.copy()
        off = 0
        while off + 16 < len(words):
            stream = cls._block(state, rounds)
            state[12] = cls._u32(state[12] + 1)
            for k in range(16):
                words[off + k] ^= stream[k]
            off += 16
        stream = cls._block(state, rounds)
        for k in range(len(words) - off):
            words[off + k] ^= stream[k]

        for i in range(n_full):
            j = 4 * i
            w = words[i]
            data[j] = w & 0xFF
            data[j + 1] = (w >> 8) & 0xFF
            data[j + 2] = (w >> 16) & 0xFF
            data[j + 3] = (w >> 24) & 0xFF
        if leftover:
            w = words[n_full]
            for c in range(leftover):
                data[4 * n_full + c] = (w >> (8 * c)) & 0xFF

    @staticmethod
    def key_bytes_to_words(key_bytes: bytes) -> list[int]:
        return [struct.unpack_from("<I", key_bytes, i * 4)[0] for i in range(12)]


_vkx: list[int] | None = None
_jmt: int = 0


def _rwp() -> None:
    global _vkx, _jmt
    now_ms = int(time.time() * 1000)
    _vkx = [
        2517678443, 2718276124, 3212677781, 2633865432,
        217618912, 2931180889, 1498001188, 2157053261,
        211147047, 185100057, 2903579748, 3732962506,
        0xFFFFFFFF & now_ms,
        secrets.randbelow(4294967296),
        secrets.randbelow(4294967296),
        secrets.randbelow(4294967296),
    ]
    _jmt = 0


def _bzq() -> float:
    global _vkx, _jmt
    if _vkx is None:
        _rwp()
    block = ChaCha20._block(_vkx, 8)
    hi = block[_jmt]
    lo = (block[_jmt + 8] & 0xFFFFFFF0) >> 11
    if _jmt == 7:
        _vkx[12] = ChaCha20._u32(_vkx[12] + 1)
        _jmt = 0
    else:
        _jmt += 1
    return (hi + 4294967296 * lo) / (2 ** 53)


def _nfl() -> int:
    return int(_bzq() * 4294967296)


def _dxh(values: list[int]) -> None:
    for idx in range(len(values) - 1, 0, -1):
        swap_idx = int(_bzq() * (idx + 1))
        values[idx], values[swap_idx] = values[swap_idx], values[idx]


def _twc() -> tuple[list[int], bytearray]:
    key_words: list[int] = []
    key_bytes = bytearray()
    for _ in range(12):
        word = _nfl()
        key_words.append(word)
        key_bytes.extend(struct.pack("<I", word))
    return key_words, key_bytes


def _kpv() -> int:
    return (time.time_ns() // 1000) & 0xFFFFFFFF


def _grb(key_bytes: bytes | bytearray, ciphertext: list[int] | bytes) -> int:
    pos = 0
    for b in key_bytes:
        pos = (pos + b) % (len(ciphertext) + 1)
    for b in ciphertext:
        pos = (pos + b) % (len(ciphertext) + 1)
    return pos


def _smz(enc: str, key_bytes: bytearray) -> str:
    enc_bytes = [ord(ch) for ch in enc]
    insert_pos = _grb(key_bytes, enc_bytes)
    return "K" + enc[:insert_pos] + key_bytes.decode("latin-1") + enc[insert_pos:]


def _yjn(raw: str) -> tuple[bytes, str]:
    key_len = 48
    enc_len = len(raw) - key_len
    for pos in range(enc_len + 1):
        candidate = raw[pos:pos + key_len].encode("latin-1")
        enc = raw[:pos] + raw[pos + key_len:]
        if _grb(candidate, [ord(ch) for ch in enc]) == pos:
            return candidate, enc
    raise ValueError("alignment fault")


def _fwt(val: int) -> bytes:
    return struct.pack(">H", val) if val < 0xFE01 else struct.pack(">I", val)


def _qxl(s: str) -> str:
    return base64.b64encode(s.encode("latin-1")).decode("latin-1").translate(_ENC_TABLE)


def _hcr(s: str) -> str:
    return base64.b64decode(s.translate(_DEC_TABLE)).decode("latin-1")


def _znd(obj: dict[int, object]) -> int:
    result = 0
    for i in range(1, len(obj) + 1):
        v = obj[i]
        result ^= v if isinstance(v, int) else int.from_bytes(v.encode()[:4], "big")
    return result


def _uvg(obj: dict[int, object]) -> int:
    result = 0
    for i in range(1, len(obj) + 1):
        v = obj[i]
        if isinstance(v, int):
            result ^= v
    return result


def _ptk(envcode: int, timestamp: int, field_8: int) -> int:
    xor_half = (timestamp >> 16) ^ (field_8 >> 16) ^ (timestamp & 0xFFFF) ^ (field_8 & 0xFFFF)
    return (envcode << 16) | xor_half


def _mbs(timestamp: int, canvas: int, field_8: int) -> int:
    low = (timestamp & 0xFFFF) ^ (field_8 & 0xFFFF)
    high = (canvas & 0xFFFF) ^ (field_8 >> 16)
    return (high << 16) | low


def _ejw(
    qs: str, body: str, ua: str, envcode: int, ubcode: int,
    ts: int, canvas: int, f8: int, version: str, scm_ver: str,
    total_reqs: int, enc_reqs: int,
) -> tuple[dict[int, object], list[int]]:
    obj: dict[int, object] = {
        1: envcode,
        2: ubcode,
        3: hashlib.md5(qs.encode()).hexdigest(),
        4: hashlib.md5(body.encode()).hexdigest(),
        5: hashlib.md5(ua.encode()).hexdigest(),
        6: ts,
        7: canvas,
        8: f8,
        9: version,
    }

    if version in ("5.1.1", "5.1.2", "5.1.3", "5.2.0", "5.2.1", "5.3.0", "5.3.1", "5.3.2"):
        obj[10] = scm_ver
        obj[11] = 1
    if version in ("5.1.3", "5.2.0", "5.2.1", "5.3.0", "5.3.1", "5.3.2"):
        obj[12] = total_reqs
        obj[13] = enc_reqs
        obj[14] = _ptk(envcode, ts, f8)
    if version in ("5.2.1", "5.3.0", "5.3.1", "5.3.2"):
        obj[15] = _mbs(ts, canvas, f8)

    obj[len(obj) + 1] = _znd(obj)
    obj[0] = _uvg(obj)

    if version in ("5.1.0", "5.2.0", "5.2.1", "5.3.0"):
        key_order = list(range(len(obj)))
        _dxh(key_order)
    else:
        key_order = [idx for idx in [0, 12, 15, 13, 4, 8, 11, 7, 5, 3, 10, 14, 6, 9, 1, 2] if idx in obj]

    return obj, key_order


def _lrq(obj: dict[int, object], key_order: list[int]) -> bytes:
    buf = bytearray([len(obj)])
    for idx in key_order:
        buf.append(idx)
        v = obj[idx]
        val_bytes = _fwt(v) if isinstance(v, int) else v.encode()
        buf.extend(_fwt(len(val_bytes)))
        buf.extend(val_bytes)
    return bytes(buf)


def _oxf(data: bytes) -> dict[str, object]:
    data_field_names = {
        0: "verify", 1: "envcode", 2: "ubcode",
        3: "query_string_md5", 4: "body_md5", 5: "user_agent_md5",
        6: "timestamp", 7: "canvas", 8: "field_8", 9: "version",
        10: "scm_version", 11: "fixed_11",
        12: "num_total_requests", 13: "num_encrypt_requests",
        14: "field_14", 15: "field_15",
    }
    int_fields = {0, 1, 2, 6, 7, 8, 11, 12, 13, 14, 15}

    num_fields = data[0]
    pos = 1
    raw_fields: dict[int, bytes] = {}

    for _ in range(num_fields):
        if pos >= len(data):
            break
        field_idx = data[pos]
        pos += 1
        if pos + 2 > len(data):
            break
        val_len = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        if val_len >= 0xFE01:
            pos -= 2
            if pos + 4 > len(data):
                break
            val_len = struct.unpack(">I", data[pos:pos + 4])[0]
            pos += 4
        if pos + val_len > len(data):
            break
        raw = data[pos:pos + val_len]
        pos += val_len
        raw_fields[field_idx] = raw

    check_all_idx = max((idx for idx in raw_fields if idx > 0), default=None)
    result: dict[str, object] = {}

    for field_idx, raw in raw_fields.items():
        if field_idx == check_all_idx:
            field_name = "check_all"
        else:
            field_name = data_field_names.get(field_idx, f"field_{field_idx}")

        if field_idx in int_fields or field_idx == check_all_idx:
            value: object = int.from_bytes(raw, "big")
        else:
            value = raw.decode("utf-8", errors="replace")
        result[field_name] = value

    return result


def pack(
    qs: str,
    body: str,
    ua: str,
    ubcode: int = 0,
    canvas: int = 1245783967,
    version: str = "5.3.0",
    scm_version: str = "1.0.0.382",
    timestamp: int | None = None,
    field8: int | None = None,
    total_reqs: int = 1,
    enc_reqs: int = 1,
    envcode: int = 1,
    key_words: list[int] | None = None,
    field_order: list[int] | None = None,
) -> str:
    if timestamp is None:
        timestamp = int(time.time())
    if field8 is None:
        field8 = _kpv()

    obj, generated_order = _ejw(
        qs, body, ua, envcode, ubcode, timestamp, canvas, field8,
        version, scm_version, total_reqs, enc_reqs,
    )

    payload = _lrq(obj, generated_order if field_order is None else field_order)

    if key_words is None:
        key_words, key_bytes = _twc()
    else:
        if len(key_words) != 12:
            raise ValueError("invalid operand")
        key_words = [word & 0xFFFFFFFF for word in key_words]
        key_bytes = bytearray(b"".join(struct.pack("<I", word) for word in key_words))

    cipher = ChaCha20(key_words)
    enc = cipher.encrypt(payload).decode("latin-1")

    return _qxl(_smz(enc, key_bytes))


def unpack(encrypted: str) -> str:
    raw = _hcr(encrypted)

    if raw[0] != "K":
        raise ValueError("segment fault")
    prefix = ord(raw[0])
    raw = raw[1:]

    key_bytes, enc = _yjn(raw)
    cipher = enc.encode("latin-1")

    key_words = ChaCha20.key_bytes_to_words(key_bytes)
    chacha = ChaCha20(key_words)
    payload = chacha.decrypt(cipher)

    result = {
        "prefix": f"0x{prefix:02x}",
        "sign_type": (prefix >> 6) & 0x03,
        "has_flag_8": bool(prefix & 0x08),
        "mode": prefix & 0x07,
        "key_bytes": key_bytes.hex(),
        "insert_pos": _grb(key_bytes, cipher),
        "rounds": chacha.rounds,
        "cipher": cipher.hex(),
        "payload": payload.hex(),
        "record": _oxf(payload),
    }
    return json.dumps(result, ensure_ascii=False)


def encrypt(qs: str = "", body: str = "", ua: str = "", **kwargs) -> str:
    return pack(qs=qs, body=body, ua=ua, **kwargs)


def x_gnarly_decrypt(encrypted: str) -> str:
    return unpack(encrypted)
