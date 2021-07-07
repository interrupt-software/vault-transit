from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto import Random
from base64 import b64decode, b64encode
from vault_client_lib import vault_client
import json
import sys

vault_client = vault_client().connect()
response = vault_client.get_datakey()

plaintext = response['data']['plaintext']
ciphertext = response['data']['ciphertext']

in_filename = sys.argv[1]
out_filename = in_filename + ".aes.mode_cbc"
chunksize = 64*1024

key = b64decode(str(plaintext).encode('utf-8'))
iv = Random.new().read(AES.block_size)

e_cipher = AES.new(key, AES.MODE_CBC, iv)

with open(in_filename, 'rb') as infile:
    with open(out_filename, 'wb') as outfile:
        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk = pad(chunk, AES.block_size)
            outfile.write(e_cipher.encrypt(chunk))

metadata = {}
metadata['iv'] = str(b64encode(e_cipher.iv).decode())
metadata['ciphertext'] = str(ciphertext)
metadata['filename'] = out_filename

filename = out_filename + ".json"

with open(filename, 'w', encoding='utf-8') as f:
    json.dump(metadata, f, ensure_ascii=False)
