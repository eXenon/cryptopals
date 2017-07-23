# HMAC-SHA1
import os
import hashlib

import base64
import binascii
import numpy as np

def to_bytes(d, format):
    if isinstance(d, (bytes, bytearray)):
        return d
    elif format == 'hex':
        return bytes(bytearray.fromhex(d))
    elif format == 'base64':
        return base64.b64decode(d)
    elif format == 'str' or format == 'bytes':
        return d.encode()
    elif format == 'int':
        return to_bytes(hex(d)[2:], 'hex')

def bytes_to(b, format):
    if not isinstance(b, (bytes, bytearray)):
        return b
    elif format == 'hex':
        return binascii.hexlify(b).decode()
    elif format == 'base64':
        return base64.b64encode(b).decode()
    elif format == 'str':
        return b.decode()
    elif format == 'bytes':
        return b
    elif format == 'int':
        return int(bytes_to(b, 'hex')[2:], 16)

def xor(d1, d2, format):
    b1,b2 = to_bytes(d1, format), to_bytes(d2, format)
    return bytes_to(bytes(char1 ^ char2 for char1,char2 in zip(b1,b2)), format)

class HMACSHA1:

    def __init__(self, key=None):
        # Generate a key at init
        self._key = key
        if key is None:
            self._key = os.urandom(16)

        # Padded key :
        self._paddedkey = self._key + b'\x00'*(64-len(self._key))

    def generate(self, m):
        # Generate a MAC
        hasher = hashlib.sha1()
        block1 = xor(self._paddedkey, b'\x36'*64, 'bytes')
        hasher.update(block1 + m)
        hash1 = hasher.digest()
        block2 = xor(self._paddedkey, b'\x5c'*64, 'bytes')
        hasher = hashlib.sha1()
        hasher.update(block2 + hash1)
        return hasher.digest()




# Webserver
import time
from flask import Flask, request
app = Flask(__name__)

hmac_oracle = HMACSHA1()

@app.route("/")
def hashmac():
    signature = request.args.get('signature')
    content = to_bytes(request.args.get('content'), 'hex')
    hmac = to_bytes(signature, 'hex')
    real_hmac = hmac_oracle.generate(content)

    # Insecure compare
    for i in range(len(real_hmac)):
        if real_hmac[i] != hmac[i]:
            return "false"
        time.sleep(0.05)
    return "true"


if __name__ == '__main__':
    app.run('127.0.0.1', 9999)
