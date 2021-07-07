import Crypto.Random
from Crypto.Cipher import AES
import hashlib
from base64 import b64decode, b64encode
import os
import random
import struct

# salt size in bytes
SALT_SIZE = 16

# number of iterations in the key generation
NUMBER_OF_ITERATIONS = 20

# the size multiple required for AES
AES_MULTIPLE = 16


def generate_key(password, salt, iterations):
    assert iterations > 0

    key = password + salt

    for i in range(iterations):
        key = hashlib.sha256(key).digest()

    return key


def pad_text(text, multiple):
    extra_bytes = len(text) % multiple

    padding_size = multiple - extra_bytes

    padding = chr(padding_size) * padding_size

    padded_text = text + padding

    return padded_text


def unpad_text(padded_text):
    padding_size = ord(padded_text[-1])

    text = padded_text[:-padding_size]

    return text


def encrypt(plaintext, password):
    salt = Crypto.Random.get_random_bytes(SALT_SIZE)

    key = generate_key(password, salt, NUMBER_OF_ITERATIONS)

    cipher = AES.new(key, AES.MODE_ECB)

    padded_plaintext = pad_text(plaintext, AES_MULTIPLE)

    ciphertext = cipher.encrypt(padded_plaintext)

    ciphertext_with_salt = salt + ciphertext

    return ciphertext_with_salt


def decrypt(ciphertext, password):
    salt = ciphertext[0:SALT_SIZE]

    ciphertext_sans_salt = ciphertext[SALT_SIZE:]

    key = generate_key(password, salt, NUMBER_OF_ITERATIONS)

    cipher = AES.new(key, AES.MODE_ECB)

    padded_plaintext = cipher.decrypt(ciphertext_sans_salt)

    plaintext = unpad_text(padded_plaintext)

    return plaintext


def main():
    plaintext = "NlMGo3etL1mwIJyIvBOpN8hOIOpOXL2qyr8o/vgxDCc="
    password = str("").encode('utf-8')
    salt = str(plaintext).encode('utf-8')
    key = generate_key(password, salt, 10)
    iv = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    in_filename = "Account-Information-Form.tiff"
    out_filename = in_filename + '.enc_AES'

    filesize = os.path.getsize(in_filename)

    chunksize = 64*1024

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += (b'\n') * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))


if __name__ == "__main__":
    main()
