# ⚡ TikTok Web Signer

### 🔐 X-Dynosaur & X-Gnarly Generation

> **Reverse-engineered TikTok Web signing implementation for SDK `5.3.2` / SCM `1.0.0.417`.**

<p align="center">

**X-DYNOSAUR**   `×`   **X-GNARLY**   `×`   **CHACha20**

</p>

<p align="center">
  <img src="https://img.shields.io/badge/SDK-5.3.2-black?style=for-the-badge&logo=tiktok" />
  <img src="https://img.shields.io/badge/SCM-1.0.0.417-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Reverse%20Engineering-⚡-purple?style=for-the-badge" />
</p>

---

## 🧬 What is this?

A Python implementation of **TikTok Web's request signing mechanisms**, focused on generating and decoding:

```text
╔══════════════════════════════════════╗
║          TikTok Web Signer           ║
╠══════════════════════════════════════╣
║  🔐 X-Dynosaur                      ║
║  🔐 X-Gnarly                        ║
║  ⚙️  SDK      5.3.2                 ║
║  ⚙️  SCM      1.0.0.417             ║
║  🧪 Browser-observed signatures     ║
╚══════════════════════════════════════╝
```

The project reconstructs the signing pipeline instead of treating the generated values as opaque strings.

---

## 🚀 Features

| Feature                         | Status |
| ------------------------------- | :----: |
| 🔐 X-Gnarly generation          |    ✅   |
| 🦖 X-Dynosaur generation        |    ✅   |
| 🔓 X-Gnarly decryption          |    ✅   |
| 🔓 X-Dynosaur decryption        |    ✅   |
| ⚡ SDK `5.3.2`                   |    ✅   |
| 🧩 SCM `1.0.0.417`              |    ✅   |
| 🔑 Dynamic key generation       |    ✅   |
| 🔎 Dynamic key extraction       |    ✅   |
| 🔐 ChaCha20 implementation      |    ✅   |
| 🧬 Custom Base64 alphabet       |    ✅   |
| 📦 Binary payload serialization |    ✅   |
| 🔬 Payload inspection           |    ✅   |
| 🔄 Encrypt / decrypt round-trip |    ✅   |

## The implementation exposes both encryption and decryption paths for the two signing formats.

# 🔥 X-Gnarly

`X-Gnarly` reconstructs a binary request-signing format containing request metadata, hashes, timestamps, version information, request counters, and integrity fields.

The implementation supports:

```python
xgnarly.encrypt(...)
```

and:

```python
xgnarly.x_gnarly_decrypt(...)
```

The decoded record can expose values including:

```text
🧩 envcode
🧩 ubcode
🔎 query_string_md5
🔎 body_md5
🔎 user_agent_md5
⏱️ timestamp
🎨 canvas
📦 version
⚙️ scm_version
🔢 request counters
🔐 integrity fields
```

---

# 🦖 X-Dynosaur

`X-Dynosaur` uses a separate tagged binary payload and signing structure.

The reconstructed format contains fields such as:

```text
🔐 checksum
⏱️ timestamp
📦 version
🎨 canvas
🔎 query_hash
🔎 body_hash
🌐 user_agent_hash
🔢 num_total_requests
🔒 num_encrypt_requests
⚙️ scm_version
🧩 ubcode
🛡️ proof / extended fields
```

The parser reconstructs the tagged payload and maps internal field identifiers into readable names.

---

# ⚙️ Signing Pipeline

```text
                ┌─────────────────┐
                │   HTTP Request  │
                └────────┬────────┘
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
      Query String              Request Body
             │                       │
             └───────────┬───────────┘
                         │
                    User-Agent
                         │
                         ▼
              ┌──────────────────┐
              │ Request Metadata │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Binary Payload   │
              └────────┬─────────┘
                       │
                       ▼
              🔑 Dynamic Key
                       │
                       ▼
                 🔐 ChaCha20
                       │
                       ▼
             Key Injection / Packing
                       │
                       ▼
             Custom Base64 Encoding
                       │
                       ▼
                🚀 Signature
```

---

# 🔐 Cryptographic Layer

The implementation contains a direct ChaCha20-style implementation including:

* quarter-round operations
* state initialization
* configurable rounds
* block generation
* keystream generation
* XOR encryption/decryption
* 32-bit word handling

## The round count is derived from the generated key material rather than being hard-coded to the conventional ChaCha20 configuration.

# 🗝️ Dynamic Keys

One of the more interesting parts of the format is the handling of the encryption key.

The signer generates:

```text
12 × uint32
      ↓
  48-byte key
```

The key is then inserted into the encrypted payload at a calculated position.

During decoding, the implementation searches for the key segment and reconstructs the original cipher state.

```text
┌──────────────────────────────────────────────┐
│                  SIGNATURE                   │
├──────────┬───────────────────┬───────────────┤
│ Header   │     Ciphertext    │   Key 🔑      │
└──────────┴───────────────────┴───────────────┘
                         ▲
                         │
                  dynamic position
```

## Both signer implementations contain dedicated key insertion and recovery logic.

# 🧬 Custom Encoding

The signatures do not use ordinary Base64 directly.

A custom alphabet is applied:

```text
Standard Base64
        ↓
Custom alphabet translation
        ↓
TikTok-style encoded output
```

The same translation layer is reversed during decoding.

---

# 🧪 Browser Validation

The repository includes **browser-observed signer outputs** for validation rather than relying exclusively on fabricated test vectors.

The captured values can be passed directly through the reconstructed decryptors:

```python
decrypted_gnarly = xgnarly.x_gnarly_decrypt(gnarly)
decrypted_dyno = xdynosaur.x_dynosaur_decrypt(dyno)
```

This allows the generated structures to be inspected and compared against observed browser behavior.

---

# 💻 Usage

### Generate both signatures

```python
from signers import xdynosaur, xgnarly

sign_opts = {
    "envcode": 65,
    "canvas": 1938040196,
    "ubcode": 0,
    "version": "5.3.2",
    "scm_version": "1.0.0.417",
    "total_reqs": 46,
    "enc_reqs": 10,
}

gnarly = xgnarly.encrypt(
    qs="",
    body=body,
    ua=user_agent,
    **sign_opts
)

dyno = xdynosaur.encrypt(
    qs="",
    body=body,
    ua=user_agent,
    **sign_opts
)

print("X-Gnarly:", gnarly)
print("X-Dynosaur:", dyno)
```

The example configuration mirrors the SDK/SCM versions represented in the current implementation.

---

# 🔍 Decode

```python
from signers import xdynosaur, xgnarly

gnarly_data = xgnarly.x_gnarly_decrypt(gnarly)
dyno_data = xdynosaur.x_dynosaur_decrypt(dyno)

print(gnarly_data)
print(dyno_data)
```

The output includes the recovered cryptographic parameters, payload, and decoded signing record.

---

# 📁 Structure

```text
.
├── 📂 signers
│   ├── 🔐 xgnarly.py
│   └── 🦖 xdynosaur.py
│
├── 🧪 main.py
├── 🔎 decrypter.py
└── 📖 README.md
```

---

# 📊 Version

```text
┌────────────────────────────────┐
│        TikTok Web Signer       │
├────────────────────────────────┤
│ SDK Version  : 5.3.2           │
│ SCM Version  : 1.0.0.417       │
│ Language     : Python          │
│ Signers      : X-Gnarly        │
│              : X-Dynosaur      │
└────────────────────────────────┘
`
```
