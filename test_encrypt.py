#!/usr/bin/env python3
import shutil, tempfile
import os
import unittest
from Crypto import Random
import encryptor_decryptor


class TestEncryptFile(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        # Remove the directory after the test
        shutil.rmtree(self.test_dir)

    def test_encrypt_decrypt(self):
        # create a 32 bytes password for encrypting the file
        password = Random.get_random_bytes(32)
        # Create a file in the temporary directory
        f = open(os.path.join(self.test_dir, 'test.txt'), 'w')
        # Write something to it
        f.write('This is a test file to test the encryption and decryption')
        f.close()
        # encrypt the file using encrypt method
        encryptor_decryptor.encrypt_file(password, os.path.join(self.test_dir, 'test.txt'))
        # remove the test.txt file
        os.remove(os.path.join(self.test_dir, 'test.txt'))
        # decrypt the file using decrypt method
        encryptor_decryptor.decrypt_file(password, os.path.join(self.test_dir, 'test.txt.enc'))
        # Read the newly created test.txt file and verify
        f = open(os.path.join(self.test_dir, 'test.txt'))
        self.assertEqual(f.read(), 'This is a test file to test the encryption and decryption')
        self.assertNotEqual(f.read(), 'some random data for not equal case')
        f.close()


if __name__ == '__main__':
    unittest.main()
