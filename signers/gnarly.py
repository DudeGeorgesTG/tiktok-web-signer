import hashlib
import time
import random

class GnarlySigner:
    def __init__(self):
        self._init_constants()
        self._init_rng()
    
    def _init_constants(self):
        self.C = [
            0xFFFFFFFF, 138, 1498001188, 211147047, 253, None, 203, 288, 9,
            1196819126, 3212677781, 135, 263, 193, 58, 18, 244, 2931180889, 240, 173,
            268, 2157053261, 261, 175, 14, 5, 171, 270, 156, 258, 13, 15, 3732962506,
            185, 169, 2, 6, 132, 162, 200, 3, 160, 217618912, 62, 2517678443, 44, 164,
            4, 96, 183, 2903579748, 3863347763, 119, 181, 10, 190, 8, 2654435769, 259,
            104, 230, 128, 2633865432, 225, 1, 257, 143, 179, 16, 600974999, 185100057,
            32, 188, 53, 2718276124, 177, 196, 4294967296, 147, 117, 17, 49, 7, 28, 12,
            266, 216, 11, 0, 45, 166, 247, 1451689750,
        ]
        self.IV = [self.C[9], self.C[69], self.C[51], self.C[92]]
        self.MASK32 = 0xFFFFFFFF
    
    def _init_rng(self):
        now_ms = int(time.time() * 1000)
        self.state = [
            self.C[44], self.C[74], self.C[10], self.C[62],
            self.C[42], self.C[17], self.C[2], self.C[21],
            self.C[3], self.C[70], self.C[50], self.C[32],
            self.C[0] & now_ms,
            random.randrange(self.C[77]),
            random.randrange(self.C[77]),
            random.randrange(self.C[77]),
        ]
        self.counter = self.C[88]
    
    def _u32(self, x):
        return x & 0xFFFFFFFF
    
    def _rotl(self, x, n):
        return self._u32((x << n) | (x >> (32 - n)))
    
    def _quarter(self, s, a, b, c, d):
        s[a] = self._u32(s[a] + s[b])
        s[d] = self._rotl(s[d] ^ s[a], 16)
        s[c] = self._u32(s[c] + s[d])
        s[b] = self._rotl(s[b] ^ s[c], 12)
        s[a] = self._u32(s[a] + s[b])
        s[d] = self._rotl(s[d] ^ s[a], 8)
        s[c] = self._u32(s[c] + s[d])
        s[b] = self._rotl(s[b] ^ s[c], 7)
    
    def _chacha_block(self, state, rounds):
        w = state[:16]
        r = 0
        while r < rounds:
            self._quarter(w, 0, 4, 8, 12)
            self._quarter(w, 1, 5, 9, 13)
            self._quarter(w, 2, 6, 10, 14)
            self._quarter(w, 3, 7, 11, 15)
            r += 1
            if r >= rounds:
                break
            self._quarter(w, 0, 5, 10, 15)
            self._quarter(w, 1, 6, 11, 12)
            self._quarter(w, 2, 7, 8, 13)
            self._quarter(w, 3, 4, 9, 14)
            r += 1
        for i in range(16):
            w[i] = self._u32(w[i] + state[i])
        return w
    
    def _bump(self, state):
        state[12] = self._u32(state[12] + 1)
    
    def _random(self):
        block = self._chacha_block(self.state, 8)
        t = block[self.counter]
        r = (block[self.counter + 8] & 0xFFFFFFF0) >> 11
        if self.counter == 7:
            self._bump(self.state)
            self.counter = 0
        else:
            self.counter += 1
        return (t + 4294967296 * r) / (2 ** 53)
    
    def _num_to_bytes(self, val):
        if val < 255 * 255:
            return [(val >> 8) & 0xFF, val & 0xFF]
        return [(val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF]
    
    def _str_to_int(self, s):
        buf = s.encode("utf8")[:4]
        acc = 0
        for b in buf:
            acc = (acc << 8) | b
        return acc & 0xFFFFFFFF
    
    def _chacha_encrypt(self, key_words, rounds, data):
        data = bytearray(data)
        n_full = len(data) // 4
        leftover = len(data) % 4
        words = [0] * ((len(data) + 3) // 4)
        
        for i in range(n_full):
            j = 4 * i
            words[i] = data[j] | (data[j+1] << 8) | (data[j+2] << 16) | (data[j+3] << 24)
        
        if leftover:
            v = 0
            base = 4 * n_full
            for c in range(leftover):
                v |= data[base + c] << (8 * c)
            words[n_full] = v
        
        o = 0
        state = key_words[:16]
        
        while o + 16 < len(words):
            stream = self._chacha_block(state, rounds)
            self._bump(state)
            for k in range(16):
                words[o + k] ^= stream[k]
            o += 16
        
        remain = len(words) - o
        stream = self._chacha_block(state, rounds)
        for k in range(remain):
            words[o + k] ^= stream[k]
        
        for i in range(n_full):
            w = words[i]
            j = 4 * i
            data[j] = w & 0xFF
            data[j+1] = (w >> 8) & 0xFF
            data[j+2] = (w >> 16) & 0xFF
            data[j+3] = (w >> 24) & 0xFF
        
        if leftover:
            w = words[n_full]
            base = 4 * n_full
            for c in range(leftover):
                data[base + c] = (w >> (8 * c)) & 0xFF
        
        return bytes(data)
    
    def _encrypt_string(self, key_words, rounds, text):
        data = [ord(ch) for ch in text]
        encrypted = self._chacha_encrypt(key_words, rounds, data)
        return "".join(chr(b) for b in encrypted)
    
    def generate(self, query_string, body, user_agent, seed=0, version="5.1.1", timestamp_ms=None):
        if timestamp_ms is None:
            timestamp_ms = int(time.time() * 1000)
        
        obj = {
            1: 1,
            2: seed,
            3: hashlib.md5(query_string.encode()).hexdigest(),
            4: hashlib.md5(body.encode()).hexdigest(),
            5: hashlib.md5(user_agent.encode()).hexdigest(),
            6: timestamp_ms // 1000,
            7: 1508145731,
            8: (timestamp_ms * 1000) % 2147483648,
            9: version
        }
        
        if version == "5.1.1":
            obj[10] = "1.0.0.314"
            obj[11] = 1
            v12 = 0
            for i in range(1, 12):
                v = obj[i]
                to_xor = v if isinstance(v, int) else self._str_to_int(v)
                v12 ^= to_xor
            obj[12] = v12 & 0xFFFFFFFF
        
        v0 = 0
        for v in obj.values():
            if isinstance(v, int):
                v0 ^= v
        obj[0] = v0 & 0xFFFFFFFF
        
        payload = [len(obj)]
        for k, v in obj.items():
            payload.append(k)
            if isinstance(v, int):
                val_bytes = self._num_to_bytes(v)
            else:
                val_bytes = list(v.encode("utf8"))
            payload.extend(self._num_to_bytes(len(val_bytes)))
            payload.extend(val_bytes)
        
        base_str = "".join(chr(b) for b in payload)
        
        key_words = []
        key_bytes = []
        round_acc = 0
        for _ in range(12):
            rnd = self._random()
            word = int(rnd * 4294967296) & 0xFFFFFFFF
            key_words.append(word)
            round_acc = (round_acc + (word & 15)) & 15
            key_bytes.extend([word & 0xFF, (word >> 8) & 0xFF, (word >> 16) & 0xFF, (word >> 24) & 0xFF])
        
        while len(key_words) < 16:
            key_words.append(0)
        
        rounds = round_acc + 5
        encrypted = self._encrypt_string(key_words, rounds, base_str)
        
        insert_pos = 0
        for b in key_bytes:
            insert_pos = (insert_pos + b) % (len(encrypted) + 1)
        for ch in encrypted:
            insert_pos = (insert_pos + ord(ch)) % (len(encrypted) + 1)
        
        key_bytes_str = "".join(chr(b) for b in key_bytes)
        final_str = chr(((1 << 6) ^ (1 << 3) ^ 3) & 0xFF) + encrypted[:insert_pos] + key_bytes_str + encrypted[insert_pos:]
        
        alphabet = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP="
        out = []
        full_len = (len(final_str) // 3) * 3
        for i in range(0, full_len, 3):
            block = (ord(final_str[i]) << 16) | (ord(final_str[i+1]) << 8) | ord(final_str[i+2])
            out.append(alphabet[(block >> 18) & 63])
            out.append(alphabet[(block >> 12) & 63])
            out.append(alphabet[(block >> 6) & 63])
            out.append(alphabet[block & 63])
        
        return "".join(out)