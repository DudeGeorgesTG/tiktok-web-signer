# TikTok Web Signer

<p align="center">
  <b>Pure Python implementation of TikTok Web Signatures</b><br>
  X-Dynosaur & X-Gnarly • Version 5.3.0
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.6%2B-3776AB?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Version-5.3.0-111827?style=for-the-badge">
  <img src="https://img.shields.io/badge/Dependencies-None-22C55E?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge">
</p>

---

## 📌 Overview

**TikTok Web Signer** is a pure-Python implementation of TikTok's web signature generation system.

It implements the generation and parsing of the following web security headers:

* `X-Dynosaur`
* `X-Gnarly`

The implementation is based on reverse engineering and analysis of TikTok's obfuscated client-side JavaScript signer.

> **Version:** `5.3.0`

---

## ✨ Features

* 🔐 X-Dynosaur generation
* 🔓 X-Dynosaur decryption
* 🔐 X-Gnarly generation
* 🔓 X-Gnarly decryption
* ⚡ Pure Python
* 📦 No external dependencies
* 🔑 Modified ChaCha20 encryption
* 🧩 Custom key embedding
* 🔤 Custom Base64 alphabet
* 🧮 Field-based payload construction
* ✅ Checksum generation
* 🔀 Obfuscated field ordering
* 🕐 Automatic timestamp generation
* ⚙️ Custom signer parameters

---

## 📁 Project Structure

```text
tiktok-signer/
│
├── signers/
│   ├── xdynosaur.py
│   └── xgnarly.py
│
└── example.py
```

The project intentionally keeps the structure minimal.

---

# 📦 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/tiktok-signer.git
cd tiktok-signer
```

No external packages are required.

### Requirements

```text
Python 3.6+
```

---

# 🚀 Usage

The easiest way to get started is to run:

```bash
python example.py
```

Or use the signers directly from Python.

### Import

```python
from signers import xdynosaur, xgnarly
from urllib.parse import urlencode
```

### Prepare Request Data

```python
body_data = {
    "mix_mode": "1",
    "username": "your_username",
    "password": "your_password",
    "aid": "1459",
    "is_sso": "false",
    "account_sdk_source": "web",
    "region": "US",
    "language": "en",
    "locale": "en",
    "did": "7679026839235233302",
    "fixed_mix_mode": "1"
}

body = urlencode(body_data)

user_agent = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36"
)
```

---

# 🔐 X-Gnarly

Generate an `X-Gnarly` header:

```python
gnarly = xgnarly.encrypt(
    qs="",
    body=body,
    ua=user_agent
)

print(f"X-Gnarly: {gnarly}")
```

---

# 🦖 X-Dynosaur

Generate an `X-Dynosaur` header:

```python
dyno = xdynosaur.encrypt(
    qs="",
    body=body,
    ua=user_agent
)

print(f"X-Dynosaur: {dyno}")
```

---

# 🔓 Decryption

Both implementations include functions for decoding generated headers.

### X-Gnarly

```python
decrypted_gnarly = xgnarly.x_gnarly_decrypt(gnarly)

print(decrypted_gnarly)
```

### X-Dynosaur

```python
decrypted_dyno = xdynosaur.x_dynosaur_decrypt(dyno)

print(decrypted_dyno)
```

The decrypted result contains the parsed signer information as a JSON string.

---

# 📚 API Reference

## X-Gnarly

### `xgnarly.encrypt()`

```python
xgnarly.encrypt(
    qs,
    body,
    ua,
    **kwargs
)
```

Generates an `X-Gnarly` header.

| Parameter     | Type   | Default       |
| ------------- | ------ | ------------- |
| `qs`          | `str`  | Required      |
| `body`        | `str`  | Required      |
| `ua`          | `str`  | Required      |
| `ubcode`      | `int`  | `0`           |
| `canvas`      | `int`  | `1245783967`  |
| `version`     | `str`  | `"5.3.0"`     |
| `scm_version` | `str`  | `"1.0.0.382"` |
| `timestamp`   | `int`  | Auto          |
| `field8`      | `int`  | Auto          |
| `total_reqs`  | `int`  | `1`           |
| `enc_reqs`    | `int`  | `1`           |
| `envcode`     | `int`  | `1`           |
| `key_words`   | `list` | Auto          |
| `field_order` | `list` | Auto          |

**Returns:** Base64-encoded `X-Gnarly` signature.

---

### `xgnarly.x_gnarly_decrypt()`

```python
xgnarly.x_gnarly_decrypt(encrypted)
```

Parses an `X-Gnarly` header.

**Returns:** JSON string containing the decoded signer fields.

---

# 🦖 X-Dynosaur

### `xdynosaur.encrypt()`

```python
xdynosaur.encrypt(
    qs,
    body,
    ua,
    **kwargs
)
```

Generates an `X-Dynosaur` header.

| Parameter     | Type   | Default       |
| ------------- | ------ | ------------- |
| `qs`          | `str`  | Required      |
| `body`        | `str`  | Required      |
| `ua`          | `str`  | Required      |
| `ubcode`      | `int`  | `0`           |
| `canvas`      | `int`  | `1245783967`  |
| `version`     | `str`  | `"5.3.0"`     |
| `scm_version` | `str`  | `"1.0.0.382"` |
| `timestamp`   | `int`  | Auto          |
| `field8`      | `int`  | Auto          |
| `total_reqs`  | `int`  | `1`           |
| `enc_reqs`    | `int`  | `1`           |
| `envcode`     | `int`  | `1`           |
| `ex_proof`    | `int`  | `0`           |
| `sign_type`   | `int`  | `1`           |
| `mode`        | `int`  | `3`           |
| `key_words`   | `list` | Auto          |

**Returns:** Base64-encoded `X-Dynosaur` signature.

---

### `xdynosaur.x_dynosaur_decrypt()`

```python
xdynosaur.x_dynosaur_decrypt(encrypted)
```

Parses an `X-Dynosaur` header.

**Returns:** JSON string containing the decoded signer fields.

---

# 🔬 How It Works

The signer combines several layers of encoding and obfuscation.

```text
┌──────────────────────┐
│   Request Parameters │
│  Query / Body / UA   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Field Construction │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│      Obfuscation     │
│   XOR / Bit Shifts   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│       Checksum       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   ChaCha20 Variant   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│     Key Embedding    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Custom Base64      │
└──────────┬───────────┘
           │
           ▼
     Signed Header
```

---

# 🔑 ChaCha20 Encryption

The implementation uses a modified ChaCha20-style construction featuring:

* Variable encryption rounds
* Custom key material
* 12-word key structure
* Custom key embedding
* Modified encryption flow

The exact behavior depends on the signer and its parameters.

---

# 🧩 Field Encoding

The signer payload is constructed from multiple fields.

Fields are processed using:

* XOR operations
* Bit shifting
* Integer manipulation
* Checksums
* Pseudo-random field ordering

This provides an additional layer of obfuscation before encryption.

---

# 🔐 Key Embedding

Key material is embedded into the generated ciphertext.

The insertion position is deterministically calculated using information derived from the key and encrypted payload.

This allows the signer to reconstruct the required key material during the decoding process.

---

# 🔤 Custom Base64

The signer uses a custom Base64 alphabet.

### Standard Base64

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=
```

### Custom Alphabet

```text
u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP=
```

The custom alphabet is used during the final encoding stage.

---

# ⚠️ Important

This project is intended for **educational, research, and reverse-engineering purposes**.

TikTok may change its web signing implementation at any time. As a result, this implementation may become outdated or stop producing accepted signatures.

Use responsibly and ensure your usage complies with applicable laws and TikTok's terms of service.

---

# 📜 Disclaimer

This project is provided **as-is**, without any guarantee of compatibility or continued functionality.

The implementation was created through analysis and reverse engineering of client-side signing logic. The author is not responsible for misuse, account restrictions, API changes, or other consequences resulting from the use of this software.

---

# 📄 License

Released under the **MIT License**.

See the `LICENSE` file for details.

---

<p align="center">
  <b>Reverse Engineer • Understand • Reimplement</b>
</p>
