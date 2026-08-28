from signers import xdynosaur
from signers import xgnarly
from urllib.parse import urlencode

body_data = {
    "mix_mode": "1",
    "username": 'EXAMPLE',
    "password": 'EXAMPLE',
    "aid": "1459",
    "is_sso": "false",
    "account_sdk_source": "web",
    "region": 'US',
    "language": 'en',
    "locale": 'en',
    "did": '7679026839235233302',
    "fixed_mix_mode": "1"
}
body = urlencode(body_data)
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
gnarly = xgnarly.encrypt(qs="", body=body, ua=user_agent)
dyno = xdynosaur.encrypt(qs="", body=body, ua=user_agent)
print(gnarly)
print('')
print(dyno)
print('')

decrypted_gnarly = xgnarly.x_gnarly_decrypt(gnarly)
decrypted_dyno = xdynosaur.x_dynosaur_decrypt(dyno)

print(decrypted_gnarly)
print('')
print(decrypted_dyno)