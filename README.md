# TikTok Web — Signature Reverse Engineering

> **Reverse-engineering study of TikTok Web's request signing pipeline, focused on `x-gnarly` and `x-dynosaur`.**

A standalone Python implementation that reconstructs the observed TikTok Web signing mechanisms from browser-generated signatures, including payload construction, custom encoding, dynamic key handling, ChaCha20-based encryption, and signature decryption.

This project is intended for **protocol research, reverse engineering, and educational analysis**.

---

## ⚡ What is this?

Modern TikTok Web requests can contain dynamically generated cryptographic parameters derived from request metadata and internal browser-side logic.

This project analyzes and reconstructs two of those mechanisms:

```text
x-gnarly
x-dynosaur
```

Instead of treating the signatures as opaque strings, the implementation breaks the process into its individual stages:

```text
Request Data
     │
     ├── Query String
     ├── Request Body
     └── User-Agent
             │
             ▼
      Metadata / Hashing
             │
             ▼
      Binary Payload
             │
             ▼
       Dynamic Key
             │
             ▼
        ChaCha20
             │
             ▼
    Key Injection / Packing
             │
             ▼
    Custom Base64 Encoding
             │
             ▼
      Final Signature
```

The reverse direction is also implemented:

```text
Final Signature
      │
      ▼
Custom Base64 Decode
      │
      ▼
Header / Key Recovery
      │
      ▼
ChaCha20 Decryption
      │
      ▼
Binary Payload
      │
      ▼
Field Reconstruction
      │
      ▼
Decoded Signing Metadata
```

---

## 🔬 Reverse-Engineered Components

### `x-gnarly`

The `x-gnarly` implementation reconstructs the observed signing format, including:

* Custom Base64 alphabet
* Dynamic 48-byte key generation
* Key insertion into the encrypted payload
* Key recovery during decryption
* ChaCha20-compatible stream construction
* Request metadata hashing
* Version-dependent fields
* Binary field serialization
* Field ordering
* Integrity/check fields
* Signature parsing and inspection

The implementation exposes both:

```python
xgnarly.encrypt(...)
```

and:

```python
xgnarly.x_gnarly_decrypt(...)
```

The decryptor reconstructs the internal record and exposes fields such as request hashes, timestamp, canvas value, version, SCM version, request counters, and encryption metadata.

---

### `x-dynosaur`

`x-dynosaur` uses a related but distinct binary format and encoding layer.

The implementation reconstructs:

* Signature header generation
* Signing mode / sign type
* Dynamic key insertion
* Custom Base64
* Tagged binary records
* Browser metadata encoding
* Hash-based fields
* Version-specific extended fields
* Payload checksum construction
* ChaCha20 encryption
* Complete payload decoding

The parser maps the binary tags back into recognizable fields such as:

```text
timestamp
version
canvas
query_hash
body_hash
user_agent_hash
num_total_requests
num_encrypt_requests
scm_version
field_8
ubcode
ex_proof_code
```

---

## 🧬 Cryptographic Layer

At the core of both implementations is a reconstructed ChaCha20-style stream cipher.

The implementation derives its round count from the generated key material and implements the quarter-round operations directly rather than relying on an external cryptographic wrapper.

The encryption pipeline is effectively:

```text
Key Words
   │
   ▼
ChaCha20 State
   │
   ▼
Keystream Blocks
   │
   ▼
Payload XOR
   │
   ▼
Encrypted Payload
```

The same mechanism is reversible, allowing captured signatures to be analyzed.

---

## 🗝️ Dynamic Key Handling

A particularly interesting part of the format is that the encryption key is not simply stored separately.

The implementation generates a 48-byte key:

```text
12 × uint32
       ↓
    48 bytes
```

The key is then inserted into the encrypted payload at a calculated position.

During decryption, the implementation searches for the key segment by testing the alignment relationship between the candidate key and remaining ciphertext.

```text
┌──────────────────────────────────────────┐
│              Packed Data                 │
├───────────────┬──────────────────────────┤
│   Ciphertext  │        48-byte key       │
└───────────────┴──────────────────────────┘
                       ▲
                       │
                recovered dynamically
```

This logic is implemented independently for both signing formats.

---

## 🧩 Binary Serialization

The signatures aren't simply encrypted JSON.

Both formats construct compact binary records before encryption.

For `x-gnarly`, fields are represented using numeric identifiers and length-prefixed values:

```text
┌────────┬──────────┬──────────────┐
│ Field  │  Length  │    Value     │
└────────┴──────────┴──────────────┘
```

The implementation reconstructs the original field names during decoding:

```python
{
    "envcode": ...,
    "ubcode": ...,
    "query_string_md5": ...,
    "body_md5": ...,
    "user_agent_md5": ...,
    "timestamp": ...,
    "canvas": ...,
    "version": ...,
    ...
}
```

`x-dynosaur` instead uses tagged records where each field is encoded as:

```text
TAG + LENGTH + VALUE
```

---

## 🧪 Browser-Derived Testing

The repository includes test values obtained from actual browser-side signer output rather than randomly generated signatures.

The test harness feeds captured signer strings into the reconstructed decryptors:

```python
decrypted_gnarly = xgnarly.x_gnarly_decrypt(gnarly)
decrypted_dyno = xdynosaur.x_dynosaur_decrypt(dyno)
```

This allows the implementation to be compared against real browser-generated values.

---

## 🚀 Usage

### Generate signatures

```python
from signers import xdynosaur, xgnarly

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

print(gnarly)
print(dyno)
```

The example configuration demonstrates request metadata such as:

```python
sign_opts = {
    "envcode": 65,
    "canvas": 1938040196,
    "ubcode": 0,
    "version": "5.3.2",
    "scm_version": "1.0.0.417",
    "total_reqs": 46,
    "enc_reqs": 10,
}
```

---

### Decode signatures

```python
from signers import xdynosaur, xgnarly

print(xgnarly.x_gnarly_decrypt(gnarly))
print(xdynosaur.x_dynosaur_decrypt(dyno))
```

The resulting JSON contains both the low-level cryptographic information and the reconstructed signing record.

---

## 📁 Project Structure

```text
.
├── signers/
│   ├── xgnarly.py
│   └── xdynosaur.py
│
├── main.py
│
├── decrypter.py
│
└── README.md
```

### `signers/xgnarly.py`

Core implementation of the `x-gnarly` format.

### `signers/xdynosaur.py`

Core implementation of the `x-dynosaur` format.

### `main.py`

Example request/signature generation and round-trip verification.

### `decrypter.py`

Example decoding workflow using browser-observed signatures.

---

## 🔍 Reverse Engineering Methodology

The implementation was reconstructed by analyzing browser-side behavior and working backwards from generated signatures.

The process involved:

```text
Browser
  │
  ├── Capture generated signature
  │
  ├── Compare signatures across requests
  │
  ├── Identify stable / dynamic regions
  │
  ├── Recover encoding scheme
  │
  ├── Recover binary field layout
  │
  ├── Recover key placement
  │
  ├── Reconstruct cipher operations
  │
  └── Validate against browser output
  │
  ▼
Python implementation
```

The goal was not merely to reproduce one static signature, but to reconstruct the underlying transformation pipeline.

---

## ⚠️ Disclaimer

This repository is intended for **educational purposes, protocol research, and reverse-engineering study**.

It does not contain TikTok source code or proprietary source files. The implementation is a reconstruction based on observable browser behavior and captured outputs.

Use responsibly and respect TikTok's Terms of Service, rate limits, authentication requirements, and applicable laws.

---

## ⭐ Highlights

```text
✓ Browser-observed signatures
✓ x-gnarly reconstruction
✓ x-dynosaur reconstruction
✓ ChaCha20 implementation
✓ Dynamic key generation
✓ Key extraction
✓ Custom Base64
✓ Binary payload parsing
✓ Request metadata hashing
✓ Version-aware serialization
✓ Encrypt / decrypt round-trip
✓ No external crypto dependency
```

---

## 🧠 Status

**Reverse-engineered • Experimental • Research**

The implementation is designed to make the signing formats understandable rather than treating them as black-box strings.

> **Captured → Dissected → Reconstructed → Reproduced.**
