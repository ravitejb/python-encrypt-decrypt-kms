#!/usr/bin/env python3
"""
This script is a wrapper to encrypt and decrypt large files using
encryptor_decryptor.py and then encrypts the key used for data encryption
using cloud KMS
"""

import os
import sys
import argparse
import base64
import io
import googleapiclient.discovery
from Crypto import Random
from google.oauth2 import service_account
import encryptor_decryptor

PROJECT_ID = "<<GCP PROJECT NAME>>"
LOCATION_ID = "<<GCP KEY RING LOCATION>>"
KEY_RING_ID = "<<KEY RING NAME>>"
CRYPTO_KEY_ID = "<<KEY NAME>>"


def encrypt(directory, keyfile):
    """Encrypts files using randomly generated password and encrypts that password using KMS
    It takes the directory to be encrypted as the argument and stores the encrypted
    data encryption key in the directory root.
    Process: 1. Creates the DEK(Data Encryptopn Key)
             2. Encrypts data files using the decrypted DEK
             3. Encrypts the DEK using KMS
    """
    # generates randam password of 32 byte length
    password = Random.get_random_bytes(32)
    plaintext_file_name = directory + "/data_encryption_password"
    if os.path.exists(plaintext_file_name):
        print("Error: Duplicate password file found {}".format(plaintext_file_name))
        sys.exit()
    with open(plaintext_file_name, 'wb') as file:
        file.write(password)
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".txt"):
                source_file_name = os.path.join(root, file)
                encryptor_decryptor.encrypt_file(password, source_file_name)
                os.remove(source_file_name)

    credentials = service_account.Credentials.from_service_account_file(keyfile)
    # Creates an API client for the KMS API.
    kms_client = googleapiclient.discovery.build('cloudkms', 'v1', credentials=credentials)

    # The resource name of the CryptoKey.
    name = 'projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}'.format(
        PROJECT_ID, LOCATION_ID, KEY_RING_ID, CRYPTO_KEY_ID)

    with io.open(plaintext_file_name, 'rb') as plaintext_file:
        plaintext = plaintext_file.read()
        plaintext = plaintext.strip()

    # Use the KMS API to encrypt the data.
    crypto_keys = kms_client.projects().locations().keyRings().cryptoKeys()
    request = crypto_keys.encrypt(
        name=name,
        body={'plaintext': base64.b64encode(plaintext).decode('ascii')})
    response = request.execute()
    ciphertext = base64.b64decode(response['ciphertext'].encode('ascii'))

    ciphertext_file_name = plaintext_file_name + ".kms"
    if os.path.exists(ciphertext_file_name):
        os.remove(ciphertext_file_name)

    # Write the encrypted data to a file.
    with io.open(ciphertext_file_name, 'wb') as ciphertext_file:
        ciphertext_file.write(ciphertext)

    print('Saved ciphertext to {}.'.format(ciphertext_file_name))

    if os.path.exists(ciphertext_file_name):
        os.remove(plaintext_file_name)


def decrypt(directory, keyfile):
    """Decrypts files using encrypted data-encryption-key stored in directory root
    Process: 1. Decrypts the DEK(Data Encryptopn Key) using KMS
             2. Decrypts data files using the decrypted DEK
    """
    credentials = service_account.Credentials.from_service_account_file(keyfile)
    # Creates an API client for the KMS API.
    kms_client = googleapiclient.discovery.build('cloudkms', 'v1', credentials=credentials)

    # The resource name of the CryptoKey.
    name = 'projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}'.format(
        PROJECT_ID, LOCATION_ID, KEY_RING_ID, CRYPTO_KEY_ID)

    ciphertext_file_name = directory + "/data_encryption_password.kms"

    if not os.path.exists(ciphertext_file_name):
        print("Error: File not found {}".format(ciphertext_file_name))
        sys.exit()

    # Read encrypted data from the input file.
    with io.open(ciphertext_file_name, 'rb') as ciphertext_file:
        ciphertext = ciphertext_file.read()

    # Use the KMS API to decrypt the data.
    crypto_keys = kms_client.projects().locations().keyRings().cryptoKeys()
    request = crypto_keys.decrypt(
        name=name,
        body={'ciphertext': base64.b64encode(ciphertext).decode('ascii')})
    response = request.execute()
    plaintext = base64.b64decode(response['plaintext'].encode('ascii'))
    password = plaintext

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".enc"):
                source_file_name = os.path.join(root, file)
                encryptor_decryptor.decrypt_file(password, source_file_name)
                os.remove(source_file_name)

    os.remove(ciphertext_file_name)


def main(argv=None):
    """creates the parser and takes the arguments form command line
    """
    if argv is None:
        argv = []
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest='command')

    encrypt_parser = subparsers.add_parser('encrypt')
    encrypt_parser.add_argument('-d', '--directory', required=True)
    encrypt_parser.add_argument('-k', '--keyfile', required=True)

    decrypt_parser = subparsers.add_parser('decrypt')
    decrypt_parser.add_argument('-d', '--directory', required=True)
    decrypt_parser.add_argument('-k', '--keyfile', required=True)

    args = parser.parse_args()

    if args.command == 'encrypt':
        encrypt(
            args.directory,
            args.keyfile)
    elif args.command == 'decrypt':
        decrypt(
            args.directory,
            args.keyfile)
    elif args.command is None:
        parser.print_help()


if __name__ == '__main__':
    main(sys.argv[1:])
