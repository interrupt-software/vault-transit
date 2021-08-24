from Crypto.Cipher import AES
from base64 import b64decode
from vault_client_lib import vault_client

import json
import os

with open('data20210824171630.json') as f:
    filedata = json.load(f)

ciphertext = filedata['ciphertext']
e_nonce = b64decode(str(filedata['nonce']).encode('utf-8'))
e_data = b64decode(str(filedata['data']).encode('utf-8'))

VAULT_ADDR = os.environ.get('VAULT_ADDR', None)
VAULT_TOKEN = os.environ.get('VAULT_TOKEN', None)
VAULT_MOUNTPOINT = os.environ.get('VAULT_MOUNTPOINT', None)
VAULT_TRANSIT_KEYRING = os.environ.get('VAULT_TRANSIT_KEYRING', None)

client = vault_client()
client.connect(VAULT_ADDR, VAULT_TOKEN)
response = client.decrypt_datakey(
    ciphertext, VAULT_TRANSIT_KEYRING, VAULT_MOUNTPOINT)
plaintext = response['data']['plaintext']

key = b64decode(str(plaintext).encode('utf-8'))
d_cipher = AES.new(key, AES.MODE_EAX, e_nonce)
d_data = d_cipher.decrypt(e_data)

try:
    print(b64decode(d_data).decode())
except ValueError:
    print("Key incorrect or message corrupted")
