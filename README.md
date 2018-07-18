# Encryption-Decryption

[![Build Status][travis-badge]][travis]  [![codecov][codecov-badge][codecov]

[travis-badge]: https://travis-ci.com/ravitejb/python-encrypt-decrypt-kms.svg?branch=master
[travis]: https://travis-ci.com/ravitejb/python-encrypt-decrypt-kms
[codecov-badge]: https://codecov.io/gh/ravitejb/python-encrypt-decrypt-kms/branch/master/graph/badge.svg
[codecov]: https://codecov.io/gh/ravitejb/python-encrypt-decrypt-kms

This repo contains the python tool to encrypt and decrypt large files by using [pycrypto](http://pythonhosted.org/pycrypto/) library and integrates with GOOGLE CLOUD KMS to encrypt tht DEK(Data Encryption Key) which there by provides a two layer security for the file

## Setup Instructions

### Pre-Requisites
Install the following on the machine that tool is running
1. Python 3 or later version, instructions can be found [here](https://cloud.google.com/python/setup#installing_python)
2. Install pip3 from the python3 package
  ```bash
  sudo apt install python3-pip
  ```
3. Install the requirements using pip3
  ```bash
  sudo pip3 install -r requirements.txt
  ```
4. A service account that has cloud KMS encryptor decryptor scopes in your GCP project to encrypt the DEK(Data Encryption Key)

*NOTE*

update the KMS details in the [encryption.py](https://github.com/ravitejb/python-encrypter-decrypter/blob/master/encryption.py#L18)

## Usage
1. To encrypt any txt file in any directory.
  ```bash
  ./encryption.py encrypt -d <directory name> -k <service account with KMS access>
  ```
2. To decrypt any already encrypted files.
  ```bash
  ./encryption.py decrypt -d <directory name> -k <service account with KMS access>
  ```
## Concept
* Encrypts any size txt files using a random generated password of 32 bytes(DEK - Data Encryption Key)
* Encrypt method encrypts all the txt files in any given directory and then encrypts the DEK with Cloud KMS(KEK - Key Encryption Key)
* Stores the encrypted DEK in the directory root for further use
* Decrypt method decrypts the DEK with KEK and then decrypts all the .enc files in give already encrypted directory
