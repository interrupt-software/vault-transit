from Crypto.Cipher import AES
from base64 import b64decode
from vault_client_lib import vault_client
import json
import sys

in_filename = sys.argv[1]
in_metadata = in_filename + ".json"
out_filename = in_filename.split(".aes", 1)[0]
metadata = None

with open(in_metadata) as f:
    metadata = json.load(f)

ciphertext = metadata['ciphertext']
e_iv = b64decode(str(metadata['iv']).encode('utf-8'))

client = vault_client()
response = client.decrypt_datakey(ciphertext)
plaintext = response['data']['plaintext']

key = b64decode(str(plaintext).encode('utf-8'))
d_cipher = AES.new(key, AES.MODE_CBC, e_iv)
chunksize = 24*1024

with open(in_filename, 'rb') as infile:
    with open(out_filename, 'wb') as outfile:
        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            outfile.write(d_cipher.decrypt(chunk))
