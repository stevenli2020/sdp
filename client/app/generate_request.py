#!/usr/bin/python
# -*- coding: utf-8 -*-

import json,sys,random
from Crypto.Hash import SHA256

with open('config','r') as f:
    CONFIG = json.loads(f.read())
USER_SVC_REQ = {}
USER_SVC_REQ['SVC_JSON'] = json.dumps(CONFIG['USER_SVC_REQ'])
USER_SVC_REQ['USER'] = CONFIG['UID']
USER_SVC_REQ['RND'] = str(random.randint(10000000,99999999))
HASH = SHA256.new()
HASH.update("".join([USER_SVC_REQ['SVC_JSON'],USER_SVC_REQ['USER'],USER_SVC_REQ['RND']]).encode("utf-8"))
USER_SVC_REQ['SIG'] = HASH.hexdigest()
print(json.dumps(USER_SVC_REQ))