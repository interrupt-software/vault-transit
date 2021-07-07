from Crypto.Cipher import AES
from base64 import b64decode
from vault_client_lib import vault_client

import json

with open('data20210706210212.json') as f:
    filedata = json.load(f)

ciphertext = filedata['ciphertext']
e_nonce = b64decode(str(filedata['nonce']).encode('utf-8'))
e_data = b64decode(str(filedata['data']).encode('utf-8'))

vault_client = vault_client().connect()
response = vault_client.decrypt_datakey(ciphertext)
plaintext = response['data']['plaintext']

key = b64decode(str(plaintext).encode('utf-8'))
d_cipher = AES.new(key, AES.MODE_EAX, e_nonce)
d_data = d_cipher.decrypt(e_data)

try:
    print(b64decode(d_data).decode())
except ValueError:
    print("Key incorrect or message corrupted")
