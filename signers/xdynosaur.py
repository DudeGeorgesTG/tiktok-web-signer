import base64
import json
import struct
import time

from signers.xgnarly import ChaCha20, _calc_insert_pos, _gen_field_8, _gen_key, _pack_uint_be



def _merge_key(cipher, key_bytes):
    pos = _calc_insert_pos(key_bytes, cipher)
    return cipher[:pos] + key_bytes + cipher[pos:]


def _split_key(packed):
    key_len = 48
    for pos in range(len(packed) - key_len + 1):
        test = packed[pos:pos + key_len]
        cipher = packed[:pos] + packed[pos + key_len:]
        if _calc_insert_pos(test, cipher) == pos:
            return test, cipher
    raise ValueError("Invalid key position")


def _custom_b64_encode(data):
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    alt = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP="
    return base64.b64encode(data).decode("latin-1").translate(str.maketrans(std, alt))


def _custom_b64_decode(text):
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    alt = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP="
    clean = "".join(text.split())
    if len(clean) % 4:
        clean += "=" * (4 - len(clean) % 4)
    return base64.b64decode(clean.translate(str.maketrans(alt, std)))


def _build_header(sign_type, mode):
    return ((sign_type & 0x03) << 6) | 0x08 | (mode & 0x07)


def _parse_header(header):
    return {
        "sign_type": (header >> 6) & 0x03,
        "has_flag_8": bool(header & 0x08),
        "mode": header & 0x07,
    }


def _hash_fnv1a(text):
    h = 2166136260
    for b in text.encode("utf-8"):
        product = ((h ^ b) * 16777619) & 0xFFFFFFFF
        h = (product + product * 32) & 0xFFFFFFFF
    return h


def _pack_hash(value):
    return (value & 0xFFFFFFFF).to_bytes(4, "big")


def _unpack_hash(data):
    if len(data) != 4:
        return None
    return int.from_bytes(data, "big")


def _decode_field(data, custom_mode=False):
    length = int.from_bytes(data[-2:], "big")
    result = []
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


def _encode_field(text):
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


def _encode_nonce_field(text):
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


def _make_record(tag, value):
    return bytes([tag]) + _pack_uint_be(len(value)) + value


def _serialize_records(records):
    buf = bytearray()
    for rec in records:
        buf.extend(_make_record(rec["tag"], rec["value"]))
    return bytes(buf)


def _parse_records(payload):
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
    result = {}
    pos = 0
    while pos < len(payload):
        if pos + 3 > len(payload):
            raise ValueError("Invalid record header")
        tag = payload[pos]
        size = int.from_bytes(payload[pos + 1:pos + 3], "big")
        pos += 3
        if pos + size > len(payload):
            raise ValueError("Invalid record data")
        value = payload[pos:pos + size]
        pos += size
        name = field_names.get(tag, f"field_{tag}")
        if tag in {43, 46, 48, 56}:
            h = _unpack_hash(value)
            result[name] = f"{h:08x}" if h is not None else value.hex()
        else:
            result[name] = _decode_field(value, custom_mode=tag in {32, 33, 34})
    return result


def _compute_field14(envcode, timestamp, field8):
    xor_half = (timestamp >> 16) ^ (field8 >> 16) ^ (timestamp & 0xFFFF) ^ (field8 & 0xFFFF)
    return ((envcode << 16) | xor_half) & 0xFFFFFFFF


FIXED_VALUE = bytes((94, 222, 223, 224, 0, 1))


def _build_payload_data(qs, body, ua, ubcode, canvas, version, scm_ver,
                        ts, field8, total_reqs, enc_reqs, envcode,
                        ex_proof, ex_scm, ex_digest, ex_proof_hash):
    entries = [
        (32, FIXED_VALUE), (33, FIXED_VALUE),
        (34, FIXED_VALUE), (35, _encode_field("0")),
        (36, _encode_field(_compute_field14(envcode, ts, field8))),
        (37, _encode_field(enc_reqs)), (38, _encode_field(envcode)),
        (39, _encode_field(ts)), (40, _encode_field(ex_proof)), (41, _encode_field("0")),
        (42, _encode_field(version)), (43, _pack_hash(_hash_fnv1a(body))),
        (44, _encode_field(canvas)), (45, _encode_field("0")),
        (46, _pack_hash(_hash_fnv1a(qs))),
        #L7N
        (47, _encode_field(total_reqs)), (48, _pack_hash(_hash_fnv1a(ua))),
        (49, _encode_field(scm_ver)), (50, _encode_field(ex_scm)),
        (51, _encode_field(ex_digest)), (52, _encode_field(field8)), (53, _encode_field("0")),
        (54, _encode_field(ubcode)), (55, _encode_field("0")),
        (56, _pack_hash(_hash_fnv1a("") if ex_proof_hash is None else ex_proof_hash)),
    ]
    
    checksum = 0
    for _, val in entries:
        checksum ^= val[1]
    entries[0] = (32, _encode_nonce_field(checksum))
    
    return _serialize_records([{"tag": t, "value": v} for t, v in entries])


def encrypt(qs, body, ua, ubcode=0, canvas=1245783967,
                       version="5.3.0", scm_version="1.0.0.382",
                       timestamp=None, field8=None, total_reqs=1,
                       enc_reqs=1, envcode=1, ex_proof=0,
                       sign_type=1, mode=3, key_words=None):
    if timestamp is None:
        timestamp = int(time.time())
    if field8 is None:
        field8 = _gen_field_8()
    
    if version == "5.3.0":
        ex_scm = "1.0.0.2695"
        ex_digest = "1b98a897ac64bcef2414bf38b8549d4c"
        ex_proof_hash = 0x0D4CBEA1
    else:
        raise ValueError(f"Version {version} not supported")
    
    payload = _build_payload_data(
        qs, body, ua, ubcode, canvas, version, scm_version,
        timestamp, field8, total_reqs, enc_reqs, envcode,
        ex_proof, ex_scm, ex_digest, ex_proof_hash
    )
    
    if key_words is None:
        key_words, key_bytes = _gen_key()
    else:
        if len(key_words) != 12:
            raise ValueError("Need 12 key words")
        key_words = [w & 0xFFFFFFFF for w in key_words]
        key_bytes = bytearray(b"".join(struct.pack("<I", w) for w in key_words))
    
    encrypted = ChaCha20(key_words).encrypt(payload)
    packed = _merge_key(encrypted, key_bytes)
    header = bytes([_build_header(sign_type, mode)])
    return _custom_b64_encode(header + packed)


def x_dynosaur_decrypt(encrypted):
    raw = _custom_b64_decode(encrypted)
    if len(raw) < 49:
        raise ValueError("Data too short")
    
    header = raw[0]
    packed = raw[1:]
    
    key_bytes, cipher = _split_key(packed)
    
    key_words = ChaCha20.key_bytes_to_words(key_bytes)
    chacha = ChaCha20(key_words)
    payload = chacha.decrypt(cipher)
    
    result = {
        "prefix": f"0x{header:02x}",
        **_parse_header(header),
        "key_bytes": key_bytes.hex(),
        "insert_pos": _calc_insert_pos(key_bytes, cipher),
        "rounds": chacha.rounds,
        "cipher": cipher.hex(),
        "payload": payload.hex(),
        "record": _parse_records(payload),
    }
    return json.dumps(result, ensure_ascii=False)
