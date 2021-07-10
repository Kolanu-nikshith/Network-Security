import socket # for socket
import sys
import base64
import pickle
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as ps
from cryptography.hazmat.primitives.asymmetric import padding
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

serverip = sys.argv[1]
serverport  = sys.argv[2]
cname = sys.argv[3]
cpassword = sys.argv[4]

# Create a socket object
s = socket.socket()
print("client socket created!")
# Define the port on which you want to connect
# connect to the server on local computer
s.connect((serverip, int(serverport)))
print("Connected to server!")
# receive data from the server
serverpub = s.recv(1024)
if not os.path.exists('clientdir'):
        os.makedirs('clientdir')

with open("clientdir/serverpub.pem", 'wb') as f:
        f.write(serverpub)
print("Received public key of server!")


with open("clientdir/serverpub.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

sessionkey = os.urandom(32)
message = cname.encode()+cpassword.encode()+sessionkey
#print(sessionkey)
enc = ciphertext = public_key.encrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
     )
 )
s.send(enc)

resp = s.recv(2)
if (resp == b"no"):
    print("User authentication failed!")
    exit()
elif (resp == b"ok"):
    print("User Authentication Successful, Access Granted!")
    print("\n\n************Available commands and their usage: ************\n")
    print("1. `cwd`  to get the current working directory")
    print("2. `listfiles` to get the list of files in the directory")
    print("3. `chgdir addr` to change the working directory")
    print("4. `cp src_addr dest_addr` , please use forward slash in the addresses  ")
    print("5. `mv src_addr dest_addr` , please use forward slash in the addresses")
    print("6. `logout` to close the connection with the server")

while True:
    print("cmd>", end="")
    inp = input()
    inp=inp.split(" ")
    if inp[0] =='listfiles':
#        dir_path = os.path.dirname(os.path.realpath(__file__))
        s.send(b"LS")
#        s.send(inp.encode())
        data = s.recv(10000)
        data = pickle.loads(data)
        print(data)
    elif inp[0] == 'cwd':
        s.send(b"CW")
        data = s.recv(1000)
        print(data.decode())
    elif inp[0] == 'logout':
        print("closing connection with server")
        s.send(b'LO')
        s.close()
        exit()
    elif inp[0] == "chgdir":
        #print(inp[1])
        s.send(b"CD")
        d=inp[1]
        s.send(d.encode())
        d1 = s.recv(100)
        if d1==b'NO':
            print("Path error. Please check")
        else:
            print("Path changed to ", d1.decode())
    elif inp[0]== "cp":
        s.send(b"CP")
        src = inp[1]
        dest = inp[2]
        #print(src, dest)

        s.send(src.encode())
        s.send(dest.encode())
        op= s.recv(2)
        if op==b'OL':
            ff = input("Destination Already exist. Do you want to overwrite. Please press 'y/n' only ")
            if ff=='n':
                print("Copy aborted as destination already exist. ")
                s.send(b"OU")
            else:
                s.send(b"OR")
                cc = s.recv(2)
                if cc ==b'OK':
                    print("Copied successfully!")
                elif cc == b'OM':
                    print("Copy failed!")
        elif op==b"OK":
            print("Copied successfully!")
        elif op==b'NO':
            print("Copy failed. Please check address")
        elif op == b'NM':
            print("source does not exist. Please check!")
    elif inp[0] =='mv':
        s.send(b'MV')
        src = inp[1]
        dest = inp[2]
        #print(src, dest)
        s.send(src.encode())
        s.send(dest.encode())
        op= s.recv(2)
        if op==b'OL':
            ff = input("Destination Already exist. Do you want to overwrite. Please press 'y/n' only ")
            if ff=='n':
                print("Move aborted as destination already exist. ")
                s.send(b"OU")
            else:
                s.send(b"OR")
                cc = s.recv(2)
                if cc ==b'OK':
                    print("Moved successfully!")
                elif cc == b'OM':
                    print("Move failed!")
        elif op==b"OK":
            print("Moved successfully!")
        elif op==b'NO':
            print("Move failed. Please check address")
        elif op == b'NM':
            print("source does not exist. Please check!")



# close the connection
s.close()	

	


