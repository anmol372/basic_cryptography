'''
References:
1. https://pycryptodome.readthedocs.io/en/latest/index.html
2. https://docs.python.org/3/library/hashlib.html
3.https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html
Library Documentation and Library Implementation Code used for reference

Steps to run on VM:

1. Upgrade to python 3.7 (https://jcutrer.com/linux/upgrade-python37-ubuntu1810)
$ sudo apt-get install python3.7
$ sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.6 1
$ sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.7 2
$ sudo update-alternatives --config python3
!!!! choose 2 (or python3.7)
$ python3 -V

2. Install pip (https://packaging.python.org/tutorials/installing-packages/#install-pip-setuptools-and-wheel):
$ wget https://bootstrap.pypa.io/get-pip.py
$ sudo python3 get-pip.py

3. Install pycryptodome (https://pycryptodome.readthedocs.io/en/latest/src/installation.html):
$ sudo apt-get install build-essential python3-dev
$ sudo python3 -m pip install pycryptodomex
$ python3 -m Cryptodome.SelfTest

'''

import json
import os
import struct
import subprocess
import filecmp
import time
import sys
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Util.Padding import pad
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import DSA
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256


class aesCBC:
    def __init__(self):
        self.start_time_key = time.process_time_ns()
        self.key = get_random_bytes(16) # 16bytes*8(bits/bytes)=128bits
        self.end_time_key = time.process_time_ns()
        self.keyperf()
        self.iv = get_random_bytes(AES.block_size)
        self.inputFile = sys.argv[1]
        self.encryptedFile = "encryptedFileAES_CBC" + self.inputFile
        self.decryptedFile = "decryptedFileAES_CBC" + self.inputFile
        self.sizeOfread = 2048


    def keyperf(self):
        print("\n--- %s nanoseconds to generate key using AESNI for CBC mode." % (self.end_time_key - self.start_time_key))

    def encrypt(self):
        fileSizeBytes = os.path.getsize(self.inputFile)
        start_time = time.process_time_ns()
        diff = start_time - start_time
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv, use_aesni=True)
        with open(self.encryptedFile, 'wb+') as fout:
            fout.write(struct.pack('<Q', fileSizeBytes))
            #save IV to output file since it's required during decryption.
            fout.write(self.iv)
        with open(self.inputFile, 'rb') as fileInput, open(self.encryptedFile, 'ab') as fout:
            while True:
                data = fileInput.read(self.sizeOfread)
                length = len(data)
                if length == 0:
                    break
                elif length % 16 != 0:
                    encryptTime = time.process_time_ns()
                    data = pad(data, AES.block_size)
                    diff += (time.process_time_ns() - encryptTime)
                ct_bytes = cipher.encrypt(data)
                fout.write(ct_bytes)
        print("--- %s nanoseconds to encrypt using AESNI in CBC mode." % (diff))
        encryptionSpeed = diff/fileSizeBytes
        print("--- Encryption Speed per byte ((Time Taken To Encrypt)/(Size of File)) = %s." % (encryptionSpeed))

    def decrypt(self):
        fileSizeBytes = os.path.getsize(self.encryptedFile)
        start_time = time.process_time_ns()
        diff = start_time - start_time
        #open encrypted file and read size of encrypted file and IV
        with open(self.encryptedFile, 'rb') as fileInput, open(self.decryptedFile, 'wb+') as fileout:
            fileSize = struct.unpack('<Q', fileInput.read(struct.calcsize('<Q')))[0]
            iv = fileInput.read(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv, use_aesni=True )
            #write decrypted file somewhere for verification:
            while True:
                data = fileInput.read(self.sizeOfread)
                #length = len(data)
                if len(data) == 0:
                    break
                decryptTime = time.process_time_ns()
                pt = cipher.decrypt(data)
                diff += (time.process_time_ns() - decryptTime)

                if fileSize > len(pt):
                    fileout.write(pt)
                else:
                    fileout.write(pt[:fileSize])
                # remove padding on last block
                fileSize = fileSize - len(pt)
        print("--- %s nanoseconds to decrypt using AESNI in CBC mode." % (diff))
        decryptionSpeed = diff/fileSizeBytes
        print("--- Decryption Speed per byte ((Time Taken To Encrypt)/(Size of File)) = %s." % (decryptionSpeed))
        if filecmp.cmp(self.inputFile, self.decryptedFile):
            print("\nCorrect Encryption and Decryption as Input File \""+ self.inputFile +"\" and Decrypted file \"" + self.decryptedFile +"\" match.\n")
        else:
            print("\nIncorrect Encryption and Decryption as Input File \""+ self.inputFile +"\" and Decrypted file \"" + self.decryptedFile +"\" dont match.\n")


class aesCTR:
    def __init__(self,keysize):
        self.start_time_key = time.process_time_ns()
        self.key = get_random_bytes(keysize)
        self.end_time_key = time.process_time_ns()
        self.keyperf()
        self.nonce = get_random_bytes(8)
        self.inputFile = sys.argv[1]
        self.encryptedFile = "encryptedFileAES_CTR_" + str(keysize*8) + self.inputFile
        self.decryptedFile = "decryptedFileAES_CTR_" + str(keysize*8) + self.inputFile

    def keyperf(self):
        print("--- %s nanoseconds to generate key using AESNI for CTR mode" % (self.end_time_key - self.start_time_key))

    def encrypt(self):
        fileSizeBytes = os.path.getsize(self.inputFile) #("/Users/anmolrastogi/Documents/Security/HW/testfile.txt")
        start_time = time.process_time_ns()
        diff = start_time - start_time
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce, use_aesni=True)
        #size of file written to output file.
        with open(self.encryptedFile, 'wb+') as fout:
            fout.write(struct.pack('<Q', fileSizeBytes))
        #Since file is encrypted in blocks of multiples of 16 bytes, last block of file might require padding. so we read 1kb at a time
        with open(self.inputFile, 'rb') as fileInput, open(self.encryptedFile, 'ab') as fout:
            data = fileInput.read(fileSizeBytes)
            encryptTime = time.process_time_ns()
            ct_bytes = cipher.encrypt(data)
            diff += (time.process_time_ns() - encryptTime)
            fout.write(ct_bytes)

        print("--- %s nanoseconds to encrypt using AESNI in CTR mode." % (diff))
        encryptionSpeed = diff/fileSizeBytes
        print("--- Encryption Speed per byte ((Time Taken To Encrypt)/(Size of File)) = %s." % (encryptionSpeed))

    def decrypt(self):
        fileSizeBytes = os.path.getsize(self.encryptedFile)
        start_time = time.process_time_ns()
        diff = start_time - start_time
        #open encrypted file and read size of encrypted file and IV
        with open(self.encryptedFile, 'rb') as fileInput, open(self.decryptedFile, 'wb+') as fileout:
            fileSize = struct.unpack('<Q', fileInput.read(struct.calcsize('<Q')))[0]

            cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce, use_aesni=True )
            #write decrypted file somewhere for verification:
            data = fileInput.read()
            decryptTime = time.process_time_ns()
            pt = cipher.decrypt(data)
            diff += (time.process_time_ns() - decryptTime)
            fileout.write(pt)
        print("--- %s nanoseconds to decrypt using AESNI in CTR mode." % (diff))
        decryptionSpeed = diff/fileSizeBytes
        print("--- Decryption Speed per byte ((Time Taken To Encrypt)/(Size of File)) = %s." % (decryptionSpeed))
        if filecmp.cmp(self.inputFile, self.decryptedFile):
            print("\nCorrect Encryption and Decryption as Input File \""+ self.inputFile +"\" and Decrypted file \"" + self.decryptedFile +"\" match.\n")
        else:
            print("\nIncorrect Encryption and Decryption as Input File \""+ self.inputFile +"\" and Decrypted file \"" + self.decryptedFile +"\" dont match.\n")

class hashOfFile:
    def __init__(self): #ch
        self.readSize = 4096
        self.inputFile = sys.argv[1]
        self.hashDigest256 = "hashDigestSHA256"
        self.hashDigest512 = "hashDigestSHA512"
        self.hashDigest3_256 = "hashDigestSHA3_256"

    def sha256(self):
        fileSizeBytes = os.path.getsize(self.inputFile)
        start_time = time.process_time_ns()
        diff = start_time - start_time
        message = hashlib.sha256()
        with open(self.inputFile, 'rb') as fileInput, open(self.hashDigest256, 'w+') as fileOut:
            while True:
                messageBlock = fileInput.read(self.readSize)
                if len(messageBlock) == 0:
                    break
                hashComputeTime = time.process_time_ns()
                message.update(messageBlock)
                diff += (time.process_time_ns() - hashComputeTime)
            fileOut.write(message.hexdigest())
        print("--- %s nanoseconds to calculate SHA256 of file." % (diff))
        perByteTiming = diff/fileSizeBytes
        print("--- SHA256 per byte speed ((Time Taken To Hash)/(Size of File)) = %s." % (perByteTiming))

    def sha512(self):
        fileSizeBytes = os.path.getsize(self.inputFile)
        start_time = time.process_time_ns()
        diff = start_time - start_time
        message = hashlib.sha512()
        with open(self.inputFile, 'rb') as fileInput, open(self.hashDigest512, 'w+') as fileOut:
            while True:
                messageBlock = fileInput.read(self.readSize)
                if len(messageBlock) == 0:
                    break
                hashComputeTime = time.process_time_ns()
                message.update(messageBlock)
                diff += (time.process_time_ns() - hashComputeTime)
            fileOut.write(message.hexdigest())
        print("--- %s nanoseconds to calculate SHA512 of file." % (diff))
        perByteTiming = diff/fileSizeBytes
        print("--- SHA512 per byte speed ((Time Taken To Hash)/(Size of File)) = %s." % (perByteTiming))

    def sha3_256(self):
        fileSizeBytes = os.path.getsize(self.inputFile)
        start_time = time.process_time_ns()
        diff = start_time - start_time
        message = hashlib.sha3_256()
        with open(self.inputFile, 'rb') as fileInput, open(self.hashDigest3_256, 'w+') as fileOut:
            while True:
                messageBlock = fileInput.read(self.readSize)
                if len(messageBlock) == 0:
                    break
                hashComputeTime = time.process_time_ns()
                message.update(messageBlock)
                diff += (time.process_time_ns() - hashComputeTime)
            fileOut.write(message.hexdigest())
        print("--- %s nanoseconds to calculate sha3_256 of file." % (diff))
        perByteTiming = diff/fileSizeBytes
        print("--- sha3_256 per byte speed ((Time Taken To Hash)/(Size of File)) = %s." % (perByteTiming))

class rsa:
    def __init__(self,keysize):
        self.keysize = keysize
        #self.key = RSA.generate(keysize)
        self.readSize = 127
        self.inputFile = sys.argv[1]
        self.publicKey = "keys/publicKey_"+str(keysize)+".pem"
        self.privateKey = "keys/privateKey_"+str(keysize)+".pem"
        self.rsaEncryptFile = "RSA_"+str(keysize)+"_encrypt_OAEP_Padding" + self.inputFile
        self.rsaDecryptFile = "RSA_"+str(keysize)+"_decrypt_OAEP_Padding" + self.inputFile
        self.storeKeys()
        self.blocksize = "blocksize"

    def storeKeys(self):
        start_time_key = time.time()
        key = RSA.generate(self.keysize)
        end_time_key = time.time()
        private_key = key.export_key()
        #os.mkdir("keys")
        try:
            os.stat("keys")
        except:
            os.mkdir("keys")
        public_key = key.publickey().export_key(pkcs=1)
        with open(self.privateKey,'wb+') as fileOut:
            fileOut.write(private_key)
        with open(self.publicKey,'wb+') as fileOut:
            fileOut.write(public_key)
        subprocess.call(['chmod', '-R', '700', 'keys/'])
        print("--- %s nanoseconds to generate keys for RSA" % (end_time_key - start_time_key))


    def encrypt(self):
        fileSizeBytes = os.path.getsize(self.inputFile)
        start_time = time.process_time_ns()
        diff = start_time - start_time
        key = RSA.importKey(open(self.publicKey, 'rb').read())
        cipher = PKCS1_OAEP.new(key)
        with open(self.inputFile, 'rb') as fileInput, open(self.rsaEncryptFile, 'wb+') as fileOut, open(self.blocksize, 'w+') as blockwrite:
            while True:
                data = fileInput.read(self.readSize)
                if len(data) == 0:
                    break
                encryptTime = time.process_time_ns()
                ct_bytes = cipher.encrypt(data)
                diff += (time.process_time_ns() - encryptTime)
                blockwrite.write(chr(len(ct_bytes)))
                fileOut.write(ct_bytes)
        print("--- %s nanoseconds to encrypt using RSA with OAEP and keysize %d" % (diff, self.keysize))
        encryptionSpeed = diff/fileSizeBytes
        print("--- Encryption Speed per byte ((Time Taken To Encrypt)/(Size of File)) = %s." % (encryptionSpeed))

    def decrypt(self):
        fileSizeBytes = os.path.getsize(self.rsaEncryptFile)
        start_time = time.process_time_ns()
        diff = start_time - start_time
        key = RSA.importKey(open(self.privateKey, 'rb').read())
        cipher = PKCS1_OAEP.new(key)
        with open(self.rsaEncryptFile, 'rb') as fileInput, open(self.rsaDecryptFile, 'wb+') as fileOut,open(self.blocksize, 'r') as blockread:
            while True:
                length = blockread.read(1)
                if not length:
                    break
                cipherT = fileInput.read(ord(length))#int(self.keysize/8))
                decryptTime = time.process_time_ns()
                plaintext = cipher.decrypt(cipherT)
                diff += (time.process_time_ns() - decryptTime)
                fileOut.write(plaintext[:self.readSize])
        print("--- %s nanoseconds to decrypt using RSA with OAEP and keysize %d" % (diff, self.keysize))
        decryptionSpeed = diff/fileSizeBytes
        print("--- Decryption Speed per byte ((Time Taken To Encrypt)/(Size of File)) = %s." % (decryptionSpeed))
        if filecmp.cmp(self.inputFile, self.rsaDecryptFile):
            print("\nCorrect Encryption and Decryption as Input File \""+ self.inputFile +"\" and Decrypted file \"" + self.rsaDecryptFile +"\" match.\n")
        else:
            print("\nIncorrect Encryption and Decryption as Input File \""+ self.inputFile +"\" and Decrypted file \"" + self.rsaDecryptFile +"\" dont match.\n")

class dsa:

    def __init__(self,keysize):
        self.readSize = 4096
        self.keysize = keysize
        self.start_time_key = time.process_time_ns()
        self.key = DSA.generate(keysize)
        self.end_time_key = time.process_time_ns()
        self.keyperf()
        self.inputFile = sys.argv[1]
        self.publicKey = "dsa_key_"+str(keysize)+".pem"
        self.signature = b''
        self.message = b''
        self.storeKeys()

    def keyperf(self):
        print("\n--- %s nanoseconds to generate DSA key." % (self.end_time_key - self.start_time_key))

    def storeKeys(self):
        with open(self.publicKey,'wb+') as fileOut:
            fileOut.write(self.key.publickey().export_key())

    def calculateSha(self):
        message = SHA256.new()
        with open(self.inputFile, 'rb') as fileInput:
            while True:
                messageBlock = fileInput.read(self.readSize)
                message.update(messageBlock)
                if len(messageBlock) == 0:
                    break
        return message

    def signMessage(self):
        hash_obj = self.calculateSha()
        signer = DSS.new(self.key, 'fips-186-3')
        signTime = time.process_time_ns()
        self.signature = signer.sign(hash_obj)
        print("--- %s nanoseconds to sign file." % (time.process_time_ns() - signTime))

    def makechange(self):
        with open(self.inputFile, 'ab') as fileOut:
            fileOut.write(b'this line needs to be deleted, why doesnt the hash change here, maybe I need to stream the creation of hash')

    def verifyMessage(self):
        pub_key = DSA.import_key(open(self.publicKey).read())
        verifier = DSS.new(pub_key, 'fips-186-3')
        hash_obj = self.calculateSha()
        signTime = time.process_time_ns()
        try:
            verifier.verify(hash_obj, self.signature)
            print("The message is authentic")
        except ValueError:
            print ("The message is not authentic")
        print("--- %s nanoseconds to verify file." % (time.process_time_ns() - signTime))

if len(sys.argv) < 2:
    print ("You must pass a file as argument!!!")
    sys.exit()
#filename = sys.argv[1]



# Using AESNI in CBC Mode:
print("\nEncryption and Decryption of a file using AES in CBC mode with 128bits key")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
aes_cbc = aesCBC()
print("AES CBC Encryption")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
aes_cbc.encrypt()
print("AES CBC Decryption")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
aes_cbc.decrypt()
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

# Using AESNI128 in CTR MODE
print("\nEncryption and Decryption of a file using AES in CTR mode with 128bits key")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
aes_ctr128 = aesCTR(16)
print("AES CTR 128bits Encryption")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
aes_ctr128.encrypt()
print("AES CTR 128bits Decryption")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
aes_ctr128.decrypt()
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

# Using AESNI256 in CTR MODE
print("\nEncryption and Decryption of a file using AES in CTR mode with 256bits key")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
aes_ctr128 = aesCTR(32)
print("AES CTR 256bits Encryption")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
aes_ctr128.encrypt()
print("AES CTR 256bits Decryption")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
aes_ctr128.decrypt()
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")


#Hash of files:
#sha256
print("Hash of File using SHA256")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
hashSHA256 = hashOfFile()
hashSHA256.sha256()
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

print("Hash of File using SHA512")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
hashSHA512 = hashOfFile()
hashSHA512.sha512()
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

print("Hash of File using SHA3_256")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
hashSHA3_256 = hashOfFile()
hashSHA3_256.sha3_256()
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

print("Encryption and Decryption of a file using 2048bit RSA with PKCS1_OAEP ")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
rsa_2048 = rsa(2048)
print("RSA 2048bit Encryption")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
rsa_2048.encrypt()
print("RSA 2048bit Decryption")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
rsa_2048.decrypt()

print("Encryption and Decryption of a file using 3072bit RSA with PKCS1_OAEP ")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
rsa_3072 = rsa(3072)
print("RSA 3072bit Encryption")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
rsa_3072.encrypt()
print("RSA 2048bit Decryption")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
rsa_3072.decrypt()
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

print("Sign and verify a file using 2048bit DSA")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
dsa_2048 = dsa(2048)
print("Sign a file using 2048bit DSA")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
dsa_2048.signMessage()
#dsa_2048.makechange()
print("Verify a file using 2048bit DSA")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
dsa_2048.verifyMessage()
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

print("Sign and verify a file using 3072bit DSA")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
dsa_3072 = dsa(3072)
print("Sign a file using 3072bit DSA")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
dsa_3072.signMessage()
#dsa_3072.makechange()
print("Verify a file using 3072bit DSA")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
dsa_3072.verifyMessage()
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
