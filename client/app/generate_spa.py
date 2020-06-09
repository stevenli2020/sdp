#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json,sys
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

with open('config','r') as f:
    CONFIG = json.loads(f.read())

SESSION_SEED = bytes.fromhex(CONFIG['SESSION_SEED'])
SESSION_SHARED_KEY = bytes.fromhex(CONFIG['SESSION_SHARED_KEY'])
SESSION_SHARED_IV = bytes.fromhex(CONFIG['SESSION_SHARED_IV'])
SESSION_UID = bytes.fromhex(CONFIG['UID'][0:16])
SESSION_COUNTER = bytes.fromhex(("0000000000000000"+hex(CONFIG['SESSION_COUNTER'])[2:])[-16:])
HASH = SHA256.new()
HASH.update(b''.join([SESSION_UID,SESSION_SEED,SESSION_COUNTER]))
SESSION_OTP = bytes.fromhex(HASH.hexdigest()[:16])
# print("UID = "+SESSION_UID.hex())
# print("CTR = "+SESSION_COUNTER.hex())
# print("OTP = "+SESSION_OTP.hex())
CIPHER_OBJ = AES.new(SESSION_SHARED_KEY, AES.MODE_CBC, SESSION_SHARED_IV)
M = b''.join([SESSION_UID,SESSION_COUNTER])
# print(M.hex())
SESSION_GMAC = CIPHER_OBJ.encrypt(M)
SPA = b''.join([SESSION_UID,SESSION_OTP,SESSION_GMAC])

#SPA format: UID_8 + OTP_8 + GMAC_16 (32 bytes in total)
#SPA will be sent after AES-CBC encryption with shared key and IV (32 bytes in total)

CIPHER_OBJ = AES.new(SESSION_SHARED_KEY, AES.MODE_CBC, SESSION_SHARED_IV)
SPA_ENC = CIPHER_OBJ.encrypt(SPA)
print(SPA_ENC.hex())




