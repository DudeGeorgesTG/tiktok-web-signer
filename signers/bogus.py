import hashlib
import base64

class BogusSigner:
    def __init__(self):
        self.standard_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        self.custom_b64 = "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe"
        self.key = bytes([0x00, 0x01, 0x0E])
        self.list_key = bytes([0xFF])
        self.fixed_val = 0x4A41279F
    
    def _custom_b64_encode(self, data):
        b64 = base64.b64encode(data).decode("ascii")
        trans = {self.standard_b64[i]: self.custom_b64[i] for i in range(len(self.standard_b64))}
        return "".join(trans.get(ch, ch) for ch in b64)
    
    def _md5(self, data):
        if isinstance(data, str):
            data = data.encode("utf8")
        return hashlib.md5(data).digest()
    
    def _rc4(self, key, data):
        s = list(range(256))
        j = 0
        key_len = len(key)
        for i in range(256):
            j = (j + s[i] + key[i % key_len]) & 0xFF
            s[i], s[j] = s[j], s[i]
        
        out = bytearray(len(data))
        i = j = 0
        for n in range(len(data)):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            k = s[(s[i] + s[j]) & 0xFF]
            out[n] = data[n] ^ k
        return bytes(out)
    
    def _xor_checksum(self, data):
        acc = 0
        for b in data:
            acc ^= b
        return acc & 0xFF
    
    def _build_payload(self, params_md5, post_md5, ua_md5, timestamp):
        parts = [
            bytes([0x40]),
            self.key,
            params_md5[14:16],
            post_md5[14:16],
            ua_md5[14:16],
            (timestamp & 0xFFFFFFFF).to_bytes(4, "big"),
            (self.fixed_val & 0xFFFFFFFF).to_bytes(4, "big")
        ]
        buffer = b"".join(parts)
        checksum = self._xor_checksum(buffer)
        buffer += bytes([checksum])
        return buffer
    
    def generate(self, query_string, body, user_agent, timestamp):
        params_md5 = self._md5(self._md5(query_string))
        post_md5 = self._md5(self._md5(body))
        ua_rc4 = self._rc4(self.key, user_agent.encode("utf8"))
        ua_b64 = base64.b64encode(ua_rc4)
        ua_md5 = self._md5(ua_b64)
        
        payload = self._build_payload(params_md5, post_md5, ua_md5, timestamp)
        encrypted = bytes([0x02]) + self.list_key + self._rc4(self.list_key, payload)
        return self._custom_b64_encode(encrypted)