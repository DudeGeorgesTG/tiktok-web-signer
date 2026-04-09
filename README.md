# TikTok Web Signer

Professional TikTok authentication & device fingerprinting toolkit (Version 5.1.1)

## Features
- X-Bogus & X-Gnarly signature generation
- Device fingerprint extraction (wid, odinId, ttwid, csrfToken, verify_fp)
- Automatic headers & cookies builder
- Proxy support
- Works on most endpoints (not latest version but stable)

## Installation

```bash
git clone https://github.com/DudeGeorgesTG/tiktok-web-signer.git
cd tiktok-web-signer
pip install requests
```

## Usage

```python
from signers.sign import TikTokSign

signer = TikTokSign()
device = signer.get_device_info()

params = {"aid": 1459, "locale": "en", "verifyFp": device["verify_fp"]}
body = "mix_mode=1&type=31"
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

x_bogus, x_gnarly = signer.generate_tokens(params, body, ua)

print(f"X-Bogus: {x_bogus}")
print(f"X-Gnarly: {x_gnarly}")
print(f"Headers: {signer.build_headers()}")
print(f"Cookies: {signer.build_cookies()}")
```

## Output Example

```json
{
  "wid": "7626855018469164574",
  "verify_fp": "verify_mnrwyyx1_RX15vX3w_DiB9_4upE_9wQY_ysx2rJVINdTq",
  "csrfToken": "4zbGKSZn-CuQZakIW5W6NQYS9NTsOZ2XKUVI",
  "ttwid": "1%7CvyhMEDoFy8HLFtl1k-yeI5ZvzGpxSJMaX2DqH2fzpAk..."
}
```

## Project Structure

```
tiktok-web-signer/
├── signers/
│   ├── __init__.py
│   ├── sign.py
│   ├── bogus.py
│   ├── gnarly.py
│   └── tiktok_fingerprint.py
├── test.py
└── README.md
```

## API Reference

### TikTokSign Methods

| Method | Parameters | Returns |
|--------|------------|---------|
| `get_device_info()` | - | `dict` with device fingerprint |
| `generate_tokens()` | `query_string, body, user_agent` | `tuple(x_bogus, x_gnarly)` |
| `build_headers()` | - | `dict` with auth headers |
| `build_cookies()` | - | `dict` with session cookies |

## Disclaimer

For educational purposes only. Comply with TikTok's Terms of Service.

## License

MIT
