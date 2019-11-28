import json
import base64
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import re, random
import os
import string

# #enkrip*******************************************************************************************************
def enkrip(keys):
    key = keys
    encryption_key = base64.b64decode(key+ "==")
    x = {'billing_number': '9282753637'}
    plaintext = json.dumps(x)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(encryption_key, AES.MODE_CTR, iv, counter= lambda : iv, segment_size=128)
    ciphertext_raw = cipher.encrypt(plaintext)
    hmac_h = base64.b64encode(hmac.new(bytes(key.encode()), ciphertext_raw, digestmod=hashlib.sha256).digest())
    ciphertext =  str( base64.b64encode(iv + hmac_h + ciphertext_raw) , "utf-8")


    print (ciphertext)

enkrip('tokopedia-5dd3cdb16270e')


# #dekrip*******************************************************************************************************
def decrypt(chprtxt):
    key = 'tokopedia-5dd3cdb16270e'
    encryption_key = base64.b64decode(key+ "==")
    ciphertext = chprtxt
    c = base64.b64decode(ciphertext.encode('utf-8'))
    iv = c[:AES.block_size]
    cipher = AES.new(encryption_key, AES.MODE_CTR, iv, counter= lambda : iv, segment_size=128)
    dec = cipher.decrypt(base64.b64decode(ciphertext[80:]))
    original_plaintext = dec.decode("utf-8").replace("\x10", "")
    hmac_h = base64.b64encode(hmac.new(bytes(key.encode()), dec, digestmod=hashlib.sha256).digest())

    print(original_plaintext)

decrypt('7RmjIcxK5XAaU0hVrqOF4VV6Z08ydlBUbWN1RGEwdk93QjZwUjVOczZ6QmN4aUY5enBBYnlySnFsZlk9R3dX6hQjyzgCrlctQx+VMB5vFaFBfZpkUsQKbh1K0j8=')
