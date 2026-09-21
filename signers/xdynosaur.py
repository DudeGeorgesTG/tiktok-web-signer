from __future__ import annotations

import base64
import json
import struct
import time

from .xgnarly import ChaCha20, _grb, _kpv, _twc, _fwt

_STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_ALT_ALPHABET = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP="
_ENC_TABLE = str.maketrans(_STD_ALPHABET, _ALT_ALPHABET)
_DEC_TABLE = str.maketrans(_ALT_ALPHABET, _STD_ALPHABET)

FIXED_VALUE = bytes((94, 222, 223, 224, 0, 1))


def _cvn(cipher: bytes, key_bytes: bytes | bytearray) -> bytes:
    pos = _grb(key_bytes, cipher)
    return cipher[:pos] + key_bytes + cipher[pos:]


def _wdp(packed: bytes) -> tuple[bytes, bytes]:
    key_len = 48
    for pos in range(len(packed) - key_len + 1):
        test = packed[pos:pos + key_len]
        cipher = packed[:pos] + packed[pos + key_len:]
        if _grb(test, cipher) == pos:
            return test, cipher
    raise ValueError("alignment fault")


def _gzt(data: bytes) -> str:
    return base64.b64encode(data).decode("latin-1").translate(_ENC_TABLE)


def _ykm(text: str) -> bytes:
    clean = "".join(text.split())
    if len(clean) % 4:
        clean += "=" * (4 - len(clean) % 4)
    return base64.b64decode(clean.translate(_DEC_TABLE))


def _bjx(sign_type: int, mode: int) -> int:
    return ((sign_type & 0x03) << 6) | 0x08 | (mode & 0x07)


def _rhl(header: int) -> dict[str, object]:
    return {
        "sign_type": (header >> 6) & 0x03,
        "has_flag_8": bool(header & 0x08),
        "mode": header & 0x07,
    }


def _qpw(text: str) -> int:
    h = 2166136260
    for b in text.encode("utf-8"):
        product = ((h ^ b) * 16777619) & 0xFFFFFFFF
        h = (product + product * 32) & 0xFFFFFFFF
    return h


def _fvs(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "big")


def _nzr(data: bytes) -> int | None:
    if len(data) != 4:
        return None
    return int.from_bytes(data, "big")


def _txc(data: bytes, custom_mode: bool = False) -> str:
    length = int.from_bytes(data[-2:], "big")
    result: list[str] = []
    for idx, target in enumerate(data[:length]):
        for code in range(32, 127):
            if custom_mode:
                val = ((code ^ (102 + idx)) + (idx & 0xAA)) ^ 0xA5
                val = (val << 1) + ((val << 1) >> 8)
                out = (val & 0xFF) ^ 0xBB
            else:
                val = (code ^ (103 + idx)) + ((idx & 0xAA) + 1)
                val = (val << 2) + ((val << 2) >> 8)
                out = (((val & 0xFF) ^ 0xBB) + 1) & 0xFF
            if out == target:
                result.append(chr(code))
                break
        else:
            return data.hex()
    return "".join(result)


def _wjb(text: object) -> bytes:
    text = str(text)
    out = bytearray(max(len(text), 4) + 2)
    for idx, ch in enumerate(text):
        val = (ord(ch) ^ (103 + idx)) + ((idx & 0xAA) + 1)
        val = (val << 2) + ((val << 2) >> 8)
        out[idx] = (((val & 0xFF) ^ 0xBB) + 1) & 0xFF
    for idx in range(len(text), 4):
        out[idx] = 0xDD + idx
    out[-2:] = len(text).to_bytes(2, "big")
    return bytes(out)


def _kmd(text: object) -> bytes:
    text = str(text)
    out = bytearray(max(len(text), 4) + 2)
    for idx, ch in enumerate(text):
        val = ((ord(ch) ^ (102 + idx)) + (idx & 0xAA)) ^ 0xA5
        val = (val << 1) + ((val << 1) >> 8)
        out[idx] = (val & 0xFF) ^ 0xBB
    for idx in range(len(text), 4):
        out[idx] = 0xDD + idx
    out[-2:] = len(text).to_bytes(2, "big")
    return bytes(out)


def _uzq(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _fwt(len(value)) + value


def _dlv(records: list[dict[str, object]]) -> bytes:
    buf = bytearray()
    for rec in records:
        buf.extend(_uzq(rec["tag"], rec["value"]))
    return bytes(buf)


def _hgn(payload: bytes) -> dict[str, object]:
    field_names = {
        32: "checksum", 33: "field_33", 34: "field_34", 35: "field_35",
        36: "field_14", 37: "num_encrypt_requests", 38: "envcode",
        39: "timestamp", 40: "ex_proof_code", 41: "field_41",
        42: "version", 43: "body_hash", 44: "canvas", 45: "field_45",
        46: "query_hash", 47: "num_total_requests", 48: "user_agent_hash",
        49: "scm_version", 50: "ex_scm_version", 51: "ex_bundle_digest",
        52: "field_8", 53: "field_53", 54: "ubcode", 55: "field_55",
        56: "ex_bundle_proof_hash",
    }
    result: dict[str, object] = {}
    pos = 0
    while pos < len(payload):
        if pos + 3 > len(payload):
            raise ValueError("unexpected EOF")
        tag = payload[pos]
        size = int.from_bytes(payload[pos + 1:pos + 3], "big")
        pos += 3
        if pos + size > len(payload):
            raise ValueError("read past end of buffer")
        value = payload[pos:pos + size]
        pos += size
        name = field_names.get(tag, f"field_{tag}")
        if tag in {43, 46, 48, 56}:
            h = _nzr(value)
            result[name] = f"{h:08x}" if h is not None else value.hex()
        else:
            result[name] = _txc(value, custom_mode=tag in {32, 33, 34})
    return result


def _srj(envcode: int, timestamp: int, field8: int) -> int:
    xor_half = (timestamp >> 16) ^ (field8 >> 16) ^ (timestamp & 0xFFFF) ^ (field8 & 0xFFFF)
    return ((envcode << 16) | xor_half) & 0xFFFFFFFF


def _ecp(
    qs: str, body: str, ua: str, ubcode: int, canvas: int,
    version: str, scm_ver: str, ts: int, field8: int,
    total_reqs: int, enc_reqs: int, envcode: int,
    ex_proof: int, ex_scm: str, ex_digest: str,
    ex_proof_hash: int | None,
) -> bytes:
    entries: list[tuple[int, bytes]] = [
        (32, FIXED_VALUE), (33, FIXED_VALUE),
        (34, FIXED_VALUE), (35, _wjb("0")),
        (36, _wjb(_srj(envcode, ts, field8))),
        (37, _wjb(enc_reqs)), (38, _wjb(envcode)),
        (39, _wjb(ts)), (40, _wjb(ex_proof)), (41, _wjb("0")),
        (42, _wjb(version)), (43, _fvs(_qpw(body))),
        (44, _wjb(canvas)), (45, _wjb("0")),
        (46, _fvs(_qpw(qs))),
        (47, _wjb(total_reqs)), (48, _fvs(_qpw(ua))),
        (49, _wjb(scm_ver)), (50, _wjb(ex_scm)),
        (51, _wjb(ex_digest)), (52, _wjb(field8)), (53, _wjb("0")),
        (54, _wjb(ubcode)), (55, _wjb("0")),
        (56, _fvs(_qpw(body) if ex_proof_hash is None else ex_proof_hash)),
    ]

    checksum = 0
    for _, val in entries:
        checksum ^= val[1]
    entries[0] = (32, _kmd(checksum))

    return _dlv([{"tag": t, "value": v} for t, v in entries])


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
    ex_proof: int = 0,
    sign_type: int = 1,
    mode: int = 3,
    key_words: list[int] | None = None,
) -> str:
    if timestamp is None:
        timestamp = int(time.time())
    if field8 is None:
        field8 = _kpv()

    if version == "5.3.0":
        ex_scm = "1.0.0.2695"
        ex_digest = "1b98a897ac64bcef2414bf38b8549d4c"
        ex_proof_hash: int | None = 0x0D4CBEA1
    elif version in ("5.3.1", "5.3.2"):
        ex_scm = "0"
        ex_digest = "0"
        ex_proof_hash = None
    else:
        raise ValueError(f"unknown descriptor: {version}")

    payload = _ecp(
        qs, body, ua, ubcode, canvas, version, scm_version,
        timestamp, field8, total_reqs, enc_reqs, envcode,
        ex_proof, ex_scm, ex_digest, ex_proof_hash,
    )

    if key_words is None:
        key_words, key_bytes = _twc()
    else:
        if len(key_words) != 12:
            raise ValueError("invalid operand")
        key_words = [w & 0xFFFFFFFF for w in key_words]
        key_bytes = bytearray(b"".join(struct.pack("<I", w) for w in key_words))

    encrypted = ChaCha20(key_words).encrypt(payload)
    packed = _cvn(encrypted, key_bytes)
    header = bytes([_bjx(sign_type, mode)])
    return _gzt(header + packed)


def unpack(encrypted: str) -> str:
    raw = _ykm(encrypted)
    if len(raw) < 49:
        raise ValueError("buffer underflow")

    header = raw[0]
    packed = raw[1:]

    key_bytes, cipher = _wdp(packed)

    key_words = ChaCha20.key_bytes_to_words(key_bytes)
    chacha = ChaCha20(key_words)
    payload = chacha.decrypt(cipher)

    result = {
        "prefix": f"0x{header:02x}",
        **_rhl(header),
        "key_bytes": key_bytes.hex(),
        "insert_pos": _grb(key_bytes, cipher),
        "rounds": chacha.rounds,
        "cipher": cipher.hex(),
        "payload": payload.hex(),
        "record": _hgn(payload),
    }
    return json.dumps(result, ensure_ascii=False)


def encrypt(qs: str = "", body: str = "", ua: str = "", **kwargs) -> str:
    return pack(qs=qs, body=body, ua=ua, **kwargs)


def x_dynosaur_decrypt(encrypted: str) -> str:
    return unpack(encrypted)from __future__ import annotations

import base64
import json
import struct
import time

from .xgnarly import ChaCha20, _grb, _kpv, _twc, _fwt

_STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_ALT_ALPHABET = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP="
_ENC_TABLE = str.maketrans(_STD_ALPHABET, _ALT_ALPHABET)
_DEC_TABLE = str.maketrans(_ALT_ALPHABET, _STD_ALPHABET)

FIXED_VALUE = bytes((94, 222, 223, 224, 0, 1))


def _cvn(cipher: bytes, key_bytes: bytes | bytearray) -> bytes:
    pos = _grb(key_bytes, cipher)
    return cipher[:pos] + key_bytes + cipher[pos:]


def _wdp(packed: bytes) -> tuple[bytes, bytes]:
    key_len = 48
    for pos in range(len(packed) - key_len + 1):
        test = packed[pos:pos + key_len]
        cipher = packed[:pos] + packed[pos + key_len:]
        if _grb(test, cipher) == pos:
            return test, cipher
    raise ValueError("alignment fault")


def _gzt(data: bytes) -> str:
    return base64.b64encode(data).decode("latin-1").translate(_ENC_TABLE)


def _ykm(text: str) -> bytes:
    clean = "".join(text.split())
    if len(clean) % 4:
        clean += "=" * (4 - len(clean) % 4)
    return base64.b64decode(clean.translate(_DEC_TABLE))


def _bjx(sign_type: int, mode: int) -> int:
    return ((sign_type & 0x03) << 6) | 0x08 | (mode & 0x07)


def _rhl(header: int) -> dict[str, object]:
    return {
        "sign_type": (header >> 6) & 0x03,
        "has_flag_8": bool(header & 0x08),
        "mode": header & 0x07,
    }


def _qpw(text: str) -> int:
    h = 2166136260
    for b in text.encode("utf-8"):
        product = ((h ^ b) * 16777619) & 0xFFFFFFFF
        h = (product + product * 32) & 0xFFFFFFFF
    return h


def _fvs(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "big")


def _nzr(data: bytes) -> int | None:
    if len(data) != 4:
        return None
    return int.from_bytes(data, "big")


def _txc(data: bytes, custom_mode: bool = False) -> str:
    length = int.from_bytes(data[-2:], "big")
    result: list[str] = []
    for idx, target in enumerate(data[:length]):
        for code in range(32, 127):
            if custom_mode:
                val = ((code ^ (102 + idx)) + (idx & 0xAA)) ^ 0xA5
                val = (val << 1) + ((val << 1) >> 8)
                out = (val & 0xFF) ^ 0xBB
            else:
                val = (code ^ (103 + idx)) + ((idx & 0xAA) + 1)
                val = (val << 2) + ((val << 2) >> 8)
                out = (((val & 0xFF) ^ 0xBB) + 1) & 0xFF
            if out == target:
                result.append(chr(code))
                break
        else:
            return data.hex()
    return "".join(result)


def _wjb(text: object) -> bytes:
    text = str(text)
    out = bytearray(max(len(text), 4) + 2)
    for idx, ch in enumerate(text):
        val = (ord(ch) ^ (103 + idx)) + ((idx & 0xAA) + 1)
        val = (val << 2) + ((val << 2) >> 8)
        out[idx] = (((val & 0xFF) ^ 0xBB) + 1) & 0xFF
    for idx in range(len(text), 4):
        out[idx] = 0xDD + idx
    out[-2:] = len(text).to_bytes(2, "big")
    return bytes(out)


def _kmd(text: object) -> bytes:
    text = str(text)
    out = bytearray(max(len(text), 4) + 2)
    for idx, ch in enumerate(text):
        val = ((ord(ch) ^ (102 + idx)) + (idx & 0xAA)) ^ 0xA5
        val = (val << 1) + ((val << 1) >> 8)
        out[idx] = (val & 0xFF) ^ 0xBB
    for idx in range(len(text), 4):
        out[idx] = 0xDD + idx
    out[-2:] = len(text).to_bytes(2, "big")
    return bytes(out)


def _uzq(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _fwt(len(value)) + value


def _dlv(records: list[dict[str, object]]) -> bytes:
    buf = bytearray()
    for rec in records:
        buf.extend(_uzq(rec["tag"], rec["value"]))
    return bytes(buf)


def _hgn(payload: bytes) -> dict[str, object]:
    field_names = {
        32: "checksum", 33: "field_33", 34: "field_34", 35: "field_35",
        36: "field_14", 37: "num_encrypt_requests", 38: "envcode",
        39: "timestamp", 40: "ex_proof_code", 41: "field_41",
        42: "version", 43: "body_hash", 44: "canvas", 45: "field_45",
        46: "query_hash", 47: "num_total_requests", 48: "user_agent_hash",
        49: "scm_version", 50: "ex_scm_version", 51: "ex_bundle_digest",
        52: "field_8", 53: "field_53", 54: "ubcode", 55: "field_55",
        56: "ex_bundle_proof_hash",
    }
    result: dict[str, object] = {}
    pos = 0
    while pos < len(payload):
        if pos + 3 > len(payload):
            raise ValueError("unexpected EOF")
        tag = payload[pos]
        size = int.from_bytes(payload[pos + 1:pos + 3], "big")
        pos += 3
        if pos + size > len(payload):
            raise ValueError("read past end of buffer")
        value = payload[pos:pos + size]
        pos += size
        name = field_names.get(tag, f"field_{tag}")
        if tag in {43, 46, 48, 56}:
            h = _nzr(value)
            result[name] = f"{h:08x}" if h is not None else value.hex()
        else:
            result[name] = _txc(value, custom_mode=tag in {32, 33, 34})
    return result


def _srj(envcode: int, timestamp: int, field8: int) -> int:
    xor_half = (timestamp >> 16) ^ (field8 >> 16) ^ (timestamp & 0xFFFF) ^ (field8 & 0xFFFF)
    return ((envcode << 16) | xor_half) & 0xFFFFFFFF


def _ecp(
    qs: str, body: str, ua: str, ubcode: int, canvas: int,
    version: str, scm_ver: str, ts: int, field8: int,
    total_reqs: int, enc_reqs: int, envcode: int,
    ex_proof: int, ex_scm: str, ex_digest: str,
    ex_proof_hash: int | None,
) -> bytes:
    entries: list[tuple[int, bytes]] = [
        (32, FIXED_VALUE), (33, FIXED_VALUE),
        (34, FIXED_VALUE), (35, _wjb("0")),
        (36, _wjb(_srj(envcode, ts, field8))),
        (37, _wjb(enc_reqs)), (38, _wjb(envcode)),
        (39, _wjb(ts)), (40, _wjb(ex_proof)), (41, _wjb("0")),
        (42, _wjb(version)), (43, _fvs(_qpw(body))),
        (44, _wjb(canvas)), (45, _wjb("0")),
        (46, _fvs(_qpw(qs))),
        (47, _wjb(total_reqs)), (48, _fvs(_qpw(ua))),
        (49, _wjb(scm_ver)), (50, _wjb(ex_scm)),
        (51, _wjb(ex_digest)), (52, _wjb(field8)), (53, _wjb("0")),
        (54, _wjb(ubcode)), (55, _wjb("0")),
        (56, _fvs(_qpw(body) if ex_proof_hash is None else ex_proof_hash)),
    ]

    checksum = 0
    for _, val in entries:
        checksum ^= val[1]
    entries[0] = (32, _kmd(checksum))

    return _dlv([{"tag": t, "value": v} for t, v in entries])


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
    ex_proof: int = 0,
    sign_type: int = 1,
    mode: int = 3,
    key_words: list[int] | None = None,
) -> str:
    if timestamp is None:
        timestamp = int(time.time())
    if field8 is None:
        field8 = _kpv()

    if version == "5.3.0":
        ex_scm = "1.0.0.2695"
        ex_digest = "1b98a897ac64bcef2414bf38b8549d4c"
        ex_proof_hash: int | None = 0x0D4CBEA1
    elif version in ("5.3.1", "5.3.2"):
        ex_scm = "0"
        ex_digest = "0"
        ex_proof_hash = None
    else:
        raise ValueError(f"unknown descriptor: {version}")

    payload = _ecp(
        qs, body, ua, ubcode, canvas, version, scm_version,
        timestamp, field8, total_reqs, enc_reqs, envcode,
        ex_proof, ex_scm, ex_digest, ex_proof_hash,
    )

    if key_words is None:
        key_words, key_bytes = _twc()
    else:
        if len(key_words) != 12:
            raise ValueError("invalid operand")
        key_words = [w & 0xFFFFFFFF for w in key_words]
        key_bytes = bytearray(b"".join(struct.pack("<I", w) for w in key_words))

    encrypted = ChaCha20(key_words).encrypt(payload)
    packed = _cvn(encrypted, key_bytes)
    header = bytes([_bjx(sign_type, mode)])
    return _gzt(header + packed)


def unpack(encrypted: str) -> str:
    raw = _ykm(encrypted)
    if len(raw) < 49:
        raise ValueError("buffer underflow")

    header = raw[0]
    packed = raw[1:]

    key_bytes, cipher = _wdp(packed)

    key_words = ChaCha20.key_bytes_to_words(key_bytes)
    chacha = ChaCha20(key_words)
    payload = chacha.decrypt(cipher)

    result = {
        "prefix": f"0x{header:02x}",
        **_rhl(header),
        "key_bytes": key_bytes.hex(),
        "insert_pos": _grb(key_bytes, cipher),
        "rounds": chacha.rounds,
        "cipher": cipher.hex(),
        "payload": payload.hex(),
        "record": _hgn(payload),
    }
    return json.dumps(result, ensure_ascii=False)


def encrypt(qs: str = "", body: str = "", ua: str = "", **kwargs) -> str:
    return pack(qs=qs, body=body, ua=ua, **kwargs)


def x_dynosaur_decrypt(encrypted: str) -> str:
    return unpack(encrypted)
