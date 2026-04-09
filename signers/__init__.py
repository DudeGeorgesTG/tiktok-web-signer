import time

from signers.bogus import BogusSigner
from signers.gnarly import GnarlySigner
from signers.tiktok_fingerprint import TikTokDeviceInfo
from signers.sign import TikTokSign

class TiktokWebSigners:
    def bogus(self, query_string, body, user_agent, timestamp):
        return BogusSigner().generate(query_string, body, user_agent, timestamp)
    
    def gnarly(self, query_string, body, user_agent, seed=0, version="5.1.1", timestamp_ms=None):
        return GnarlySigner().generate(query_string, body, user_agent, seed, version, timestamp_ms)
    
    def generate_tokens(self, query_string, body, user_agent, timestamp=None, seed=0, version="5.1.1"):
        if timestamp is None:
            timestamp = int(time.time())
        
        return (
            self.bogus(query_string, body, user_agent, timestamp),
            self.gnarly(query_string, body, user_agent, seed, version, timestamp * 1000 if timestamp else None)
        )

import sys
sys.modules[__name__] = TiktokWebSigners()