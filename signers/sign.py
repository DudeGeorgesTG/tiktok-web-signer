import time
from urllib.parse import urlencode
import requests
from signers.tiktok_fingerprint import TikTokDeviceInfo
from signers.bogus import BogusSigner
from signers.gnarly import GnarlySigner

class TikTokSign:
    def __init__(self, proxy=None):
        self.proxy = proxy
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.fingerprint = TikTokDeviceInfo(proxy=proxy)
        self.device_info = None
        
    def get_device_info(self):
        self.device_info = self.fingerprint.get_device_info()
        return self.device_info
    
    def get_verify_fp(self):
        if not self.device_info:
            self.get_device_info()
        return self.device_info.get("verify_fp")
    
    def get_ttwid(self):
        if not self.device_info:
            self.get_device_info()
        return self.device_info.get("ttwid")
    
    def get_csrf_token(self):
        if not self.device_info:
            self.get_device_info()
        return self.device_info.get("csrfToken")
    
    def _to_string(self, data):
        if isinstance(data, dict):
            return urlencode(data)
        return str(data)
    
    def bogus_sign(self, query_string, body, user_agent, timestamp):
        query_string = self._to_string(query_string)
        body = self._to_string(body)
        return BogusSigner().generate(query_string, body, user_agent, timestamp)
    
    def gnarly_sign(self, query_string, body, user_agent, seed=0, version="5.1.1", timestamp_ms=None):
        query_string = self._to_string(query_string)
        body = self._to_string(body)
        return GnarlySigner().generate(query_string, body, user_agent, seed, version, timestamp_ms)
    
    def generate_tokens(self, query_string, body, user_agent, timestamp=None):
        if timestamp is None:
            timestamp = int(time.time())
        
        x_bogus = self.bogus_sign(query_string, body, user_agent, timestamp)
        x_gnarly = self.gnarly_sign(query_string, body, user_agent, timestamp_ms=timestamp * 1000)
        
        return x_bogus, x_gnarly
    
    def build_url(self, base_url, params, x_bogus, x_gnarly):
        query_string = urlencode(params)
        return f"{base_url}?{query_string}&X-Bogus={x_bogus}&X-Gnarly={x_gnarly}"
    
    def build_headers(self, custom_headers=None):
        headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
            'accept': 'application/json, text/javascript',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://www.tiktok.com',
            'referer': 'https://www.tiktok.com/',
            'x-tt-passport-csrf-token': self.get_csrf_token(),
            'x-tt-passport-ttwid-ticket': self.get_ttwid()
        }
        if custom_headers:
            headers.update(custom_headers)
        return headers
    
    def build_cookies(self):
        if not self.device_info:
            self.get_device_info()
        
        cookies = {
            'tt_csrf_token': self.device_info.get('csrfToken', ''),
            'ttwid': self.device_info.get('ttwid', ''),
            'odin_tt': self.device_info.get('odinId', ''),
            's_v_web_id': self.device_info.get('verify_fp', '')
        }
        return cookies