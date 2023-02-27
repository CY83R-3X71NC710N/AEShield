

#!/usr/bin/env python
# CY83R-3X71NC710N Copyright 2023

import os
import hashlib
import base64
import pyAesCrypt
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Generate a 16-byte random IV
iv = os.urandom(16)

# Get a key produced from the user's given password in PBKDF2 format
password = input("Please enter your password: ")
salt = b"salt_" # salt can be any string
kdf = PBKDF2(password, salt, dkLen=32, count=100000)
key = kdf[:16] # use only 16 bytes

# Encrypt the data
data = input("Please enter the data to be encrypted: ")
enc_data = pyAesCrypt.encrypt(data, key, iv)

# Generate an HMAC signature
hmac_key = b"hmac_key" # key can be any string
hmac = hashlib.pbkdf2_hmac('sha256', enc_data, hmac_key, 100000)
hmac_signature = base64.b64encode(hmac)

# Decrypt the data
dec_data = pyAesCrypt.decrypt(enc_data, key, iv)

# Verify the HMAC signature
hmac_verify = hashlib.pbkdf2_hmac('sha256', dec_data, hmac_key, 100000)
if hmac_verify == hmac:
    print("HMAC signature verified")
else:
    print("HMAC signature not verified")
