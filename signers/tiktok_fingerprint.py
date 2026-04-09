import requests
import re
import json
import random
import string
import time

class TikTokDeviceInfo:
    
    def __init__(self, proxy=None):
        self.proxy = proxy
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.ttwid = None
        self.device_info = {}
        
    def get_ttwid(self):
        url = "https://ttwid.bytedance.com/ttwid/union/register/"
        
        data = {
            "region": "us",
            "aid": 1768,
            "needFid": False,
            "service": "www.tiktok.com",
            "migrate_info": {"ticket": "", "source": "node"},
            "cbUrlProtocol": "https",
            "union": True
        }
        
        response = requests.post(url, json=data, proxies=self.proxies)
        ttwid = response.cookies.get("ttwid")
        self.ttwid = ttwid
        return ttwid
    
    def fetch_page_content(self):
        url = "https://www.tiktok.com/explore"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        }
        
        response = requests.get(url, headers=headers, proxies=self.proxies)
        response.raise_for_status()
        return response.text
    
    def extract_device_info(self, html_content):
        patterns = {
            "language": r'"language":"([^"]+)"',
            "region": r'"region":"([^"]+)"',
            "appType": r'"appType":"([^"]+)"',
            "wid": r'"wid":"(\d{19})"',
            "webIdCreatedTime": r'"webIdCreatedTime":"(\d+)"',
            "odinId": r'"odinId":"(\d+)"',
            "nonce": r'"nonce":"([^"]+)"',
            "botType": r'"botType":"([^"]+)"',
            "requestId": r'"requestId":"(\d+)"',
            "csrfToken": r'"csrfToken":"([^"]+)"',
            "encryptedWebid": r'"encryptedWebid":"([^"]+)"'
        }
        
        result = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, html_content)
            result[key] = match.group(1) if match else None
        
        result["ttwid"] = self.ttwid
        result["verify_fp"] = self.get_verify_fp()
        return result
    
    def get_device_info(self):
        self.get_ttwid()
        html_content = self.fetch_page_content()
        self.device_info = self.extract_device_info(html_content)
        return self.device_info
    
    def get_verify_fp(self, timestamp: int = None) -> str:
        base_str = string.digits + string.ascii_uppercase + string.ascii_lowercase
        t = len(base_str)
        milliseconds = timestamp or int(round(time.time() * 1000))
        base36 = ""

        while milliseconds > 0:
            milliseconds, remainder = divmod(milliseconds, 36)
            if remainder < 10:
                base36 = str(remainder) + base36
            else:
                base36 = chr(ord("a") + remainder - 10) + base36

        o = [""] * 36
        o[8] = o[13] = o[18] = o[23] = "_"
        o[14] = "4"

        for i in range(36):
            if not o[i]:
                n = int(random.random() * t)
                if i == 19:
                    n = 3 & n | 8
                o[i] = base_str[n]

        return "verify_" + base36 + "_" + "".join(o)

