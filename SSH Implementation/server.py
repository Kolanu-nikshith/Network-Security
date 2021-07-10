
import socket # for socket
import sys
import pickle
from pathlib import Path
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import shutil

from cryptography.hazmat.primitives import padding as ps
from cryptography.hazmat.primitives.asymmetric import padding
import os
#import padding from cryptography.hazmat.primitives
from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes






def RSAkeygen():
    l=1024
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=l,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    privname = 'serverpriv' + ".pem"
    pubname = 'serverpub' + ".pem"
    if not os.path.exists('serverkeys'):
        os.makedirs('serverkeys')
    if not os.path.exists('UserCredentials'):
        os.makedirs('UserCredentials')
    
    data_folder = "serverkeys/"

    fa = "serverkeys/serverpriv.pem"
    fa1 = "serverkeys/serverpub.pem"


    with open('serverkeys/serverpriv.pem', 'wb') as f:
        f.write(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('serverkeys/serverpub.pem', 'wb') as f:
        f.write(public_pem)
        
    with open("users.txt", 'r') as f:
        Lines = f.readlines()

        count = 0
        # Strips the newline character
        for line in Lines:
            uname = line.strip()
            count += 1
            iv = os.urandom(16)
            #print('iv:',iv)
            base64iv = base64.b64encode(iv).decode('utf-8')
            zeros = b'0000000000000000'
            key = b"1234567890123456"
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(zeros) + encryptor.finalize()
            #print(ct)
            base64ct = base64.b64encode(ct).decode('utf-8')
            
            fa2 = "UserCredentials/"+uname+".txt"
            #fa = data_folder / uname 

            with open(fa2, 'w') as f:
                f.write(uname+"\n")
                f.write(base64iv+"\n")
                f.write(base64ct)
            
            

RSAkeygen()

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("Socket successfully created")
except socket.error as err:
    print ("socket creation failed with error %s" %(err))

#ad = sys.argv[1]
port = int(sys.argv[1])
s.bind(('', port))         
print ("socket binded to %s" %(port)) 
  
s.listen(5)     
print ("socket is listening")  
a=0
def confunc():
    global c,addr 
    c, addr = s.accept()     
    print ('Got connection from', addr )
    pubname = 'serverpub' + ".pem"
    fa = 'serverkeys/serverpub.pem'
    print("sending server public key")
    with open('serverkeys/serverpub.pem', 'rb') as f:
        pubkey = f.read()
    c.send(pubkey) 
    credentials = c.recv(128)
    print("Received Credentails from client. Verifying them...")
    fa = "serverkeys/serverpriv.pem"
    #fa = data_folder / pubname

    with open(fa, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    pt = private_key.decrypt(credentials,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cname = pt[0:8]
    cpassword = pt[8:24]
    csession = pt[24:]
    print(cname.decode())
    #print(cpassword)
    #print(csession)
    a=0
    with open("UserCredentials/"+cname.decode()+".txt", 'rb') as f:
            Lines = f.readlines()
            count = 0
            # Strips the newline character
            for line in Lines:
                if count==0:
                    count=1
                elif count==1:
                    count += 1
                    iv = base64.b64decode(line)
                    #print(iv)
                elif count==2:
                    cipher = Cipher(algorithms.AES(b'1234567890123456'), modes.CBC(iv), default_backend())
                    decryptor = cipher.decryptor()
                    ct = base64.b64decode(line)
                    dec = decryptor.update(ct) + decryptor.finalize()
                    #print(dec)
                    if(dec == b'0000000000000000'):
                        print("User Authentication Successful!")
                        c.send(b"ok")
                        a=1
                    else:
                        print("User Authentication Failed! Waiting for new client")
                        c.send(b'no')
                        confunc()
                

confunc()   

while True:
    cmd = c.recv(2)
    if cmd == b"LS":
        inp = os.getcwd()
        a = os.listdir(inp)
        print("listfiles command received!")
        data=pickle.dumps(a)
        c.send(data)
    if cmd == b"CW":
        inp = os.getcwd()
        print("cwd command received!")
        inpp = inp.encode()
        c.send(inpp)
    if cmd == b"LO":
        try:
            print("Logout command received! closed session") 
            #print("Waiting for new client...")
            #confunc()
            #c.close()
            exit()
        except Exception:
            pass
    if cmd== b'CD':
        data = c.recv(100)
        print(data)
        print("cd command received!")
        try:
            os.chdir(data)
            print(os.getcwd())
            d = os.getcwd()
            c.send(d.encode())
        except:
            print("Path error. Please check")
            c.send(b"NO")
    if cmd == b'CP':
        src = c.recv(100)
        dest = c.recv(100)
        src= src.decode()
        dest = dest.decode()
        print("cp command received!")
        print("src : ", src)
        print("dest : ", dest)
        file0 = Path(src)
        file1 = Path(dest)
        if file0.exists():
            if file1.exists ():
                c.send(b"OL")
                dd = c.recv(2)
                dd = dd.decode()
                if dd == 'OR':
                    try:
                        shutil.rmtree(dest)
                        shutil.copytree(src, dest)
                        c.send(b"OK")
                    except:    
                        c.send(b"OM")
                elif dd=="OU":
                    print("Copy aborted by user as destination already exist!")
                    
            else:
                try:
                    shutil.copytree(src, dest)
                    c.send(b"OK")
                except:
                    print("copying failed, check address properly")
                    c.send(b"NO")
        else:
            print("Src address not exist")
            c.send(b"NM")
    if cmd == b'MV':
        src = c.recv(100)
        dest = c.recv(100)
        print("mv command received!")
        src= src.decode()
        dest = dest.decode()
        print("src : ", src)
        print("dest : ", dest)
        file0 = Path(src)
        file1 = Path(dest)
        if file0.exists():
            if file1.exists ():
                c.send(b"OL")
                dd = c.recv(2)
                dd = dd.decode()
                if dd == 'OR':
                    try:
                        shutil.rmtree(dest)
                        shutil.copytree(src, dest)
                        shutil.rmtree(src)
                        c.send(b"OK")
                    except:    
                        c.send(b"OM")
                elif dd=="OU":
                    print("Move aborted by user as destination already exist!")
            else:
                try:
                    shutil.copytree(src, dest)
                    shutil.rmtree(src)
                    c.send(b"OK")
                except:
                    print("Moving failed, check address properly")
                    c.send(b"NO")
        else:
            print("Src address not exist")
            c.send(b"NM")

        
#        data=pickle.dumps(a)

# Close the connection with the client 
c.close() 

