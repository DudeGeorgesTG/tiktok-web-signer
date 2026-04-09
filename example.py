from signers.sign import TikTokSign
from urllib.parse import urlencode
from dataclasses import dataclass

@dataclass
class TikTokRequest:
    aid: int = 1459
    locale: str = "en"
    body: str = "mix_mode=1&type=31"
    ua: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    def __post_init__(self):
        self.signer = TikTokSign()
        self.device = self.signer.get_device_info()
    
    @property
    def query(self) -> str:
        return urlencode({
            "aid": self.aid, 
            "locale": self.locale, 
            "verifyFp": self.device["verify_fp"]
        })
    
    @property
    def tokens(self) -> tuple:
        return self.signer.generate_tokens(self.query, self.body, self.ua)
    
    @property
    def x_bogus(self) -> str:
        return self.tokens[0]
    
    @property
    def x_gnarly(self) -> str:
        return self.tokens[1]
    
    @property
    def headers(self) -> dict:
        return self.signer.build_headers()
    
    @property
    def cookies(self) -> dict:
        return self.signer.build_cookies()
    
    def display(self) -> None:
        print(f"WID: {self.device['wid']}")
        print(f"Verify FP: {self.device['verify_fp']}")
        print(f"X-Bogus: {self.x_bogus}")
        print(f"X-Gnarly: {self.x_gnarly}")
        print(f"Headers: {self.headers}")
        print(f"Cookies: {self.cookies}")

if __name__ == "__main__":
    req = TikTokRequest()
    req.display()