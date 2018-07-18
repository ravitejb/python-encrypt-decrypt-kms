#!/usr/bin/env python3
"""
This script helps to encrypt and decrypt large files using
pycrypto library and using AES algorithm in CBC mode
"""

import os
import struct
import hashlib
import base64

from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def hash_for_file(file_name, block_size=2 ** 20):
    """ Generates the hash for provided file

        block_size:
            Sets the size of the block which the function
            uses to read and updates the hash.
    """
    hasher = SHA256.new()
    source_file = open(file_name, "r")

    while True:
        data = source_file.read(block_size)
        if not data:
            break
        hasher.update(data.encode('utf-8'))

    source_file.close()
    return hasher.hexdigest()


def encrypt_file(password, in_filename, chunksize=64 * 1024):
    """ Encrypts a file using AES (CBC mode) with the
        given password.

        password:
            The encryption key string that must be 32 bytes long.

        in_filename:
            Name of the input file

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file.
            chunksize must be divisible by 16.
    """

    out_filename = in_filename + '.enc'
    base64_filename = in_filename + '.base64encoded'
    key = hashlib.sha256(password).digest()
    iv = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    with open(in_filename, 'rb') as sourcefile:
        with open(base64_filename, 'wb') as base64_file:
            base64_string = base64.b64encode(sourcefile.read())
            base64_file.write(base64_string)

    filesize = os.path.getsize(base64_filename)

    with open(base64_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)
            source_hash = hash_for_file(in_filename)
            outfile.write(source_hash.encode('utf-8'))

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += (' ' * (16 - len(chunk) % 16)).encode('utf-8')

                outfile.write(encryptor.encrypt(chunk))

    print("Source: {} {}".format(in_filename, source_hash))
    print("Encoded: {}".format(out_filename))

    os.remove(base64_filename)


def decrypt_file(password, in_filename, chunksize=24 * 1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key.

        password:
            The decryption key string that must be 32 bytes long.

        in_filename:
            Name of the input file

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file.
            chunksize must be divisible by 16.
    """

    out_filename = os.path.splitext(in_filename)[0] + '.base64decoded'
    base64_filename = os.path.splitext(in_filename)[0]
    key = hashlib.sha256(password).digest()
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        source_hash = infile.read(64)
        source_hash = source_hash.decode('utf-8')
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)

    with open(out_filename, 'rb') as sourcefile:
        with open(base64_filename, 'wb') as base64_file:
            base64_string = base64.b64decode(sourcefile.read())
            base64_file.write(base64_string)

    decoded_hash = hash_for_file(base64_filename)
    print("Decoded: {} {}".format(base64_filename, decoded_hash))
    print("Hash check: {}".format("Passed" if source_hash == decoded_hash else "Failed"))
    os.remove(out_filename)
