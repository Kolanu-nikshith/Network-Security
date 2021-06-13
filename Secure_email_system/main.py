import sys
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
#import padding from cryptography.hazmat.primitives

from cryptography.hazmat.primitives import padding as ps
from cryptography.hazmat.primitives.asymmetric import padding as pa
import os
#import padding from cryptography.hazmat.primitives
from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes




def utf8(s: bytes):
    return str(s, 'utf-8')


def RSAkeygen(user, l):
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
    privname = str(user) + "_pri_" + str(l) + ".pem"
    pubname = str(user) + "_pub_" + str(l) + ".pem"

    with open(privname, 'wb') as f:
        f.write(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(pubname, 'wb') as f:
        f.write(public_pem)

def only_conf_ENC(sender, receiver, inpfile,outfile, symEncType, keylen, te):
    sender = sender.strip()
    recv = receiver.strip()
    if symEncType == 0:
        # AES 256 bit key encryption
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        s='r'
        if te==1:
            s='rb'
        fi = open(inpfile, s)
        msg = fi.read()
        if te!=1:
            message = msg.encode()
        else:
            message = msg

        padder = ps.PKCS7(128).padder()
        message = padder.update(message)
        message += padder.finalize()

        ct = encryptor.update(message) + encryptor.finalize()

        recvpub = str(recv) + "_pub_" + str(keylen) + ".pem"

        with open(recvpub, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        e_key = public_key.encrypt(key,
                                   pa.OAEP(mgf=pa.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                label=None))
        al = sender + "_to_" + recv + "_enc_aes_"+str(keylen)+"_CONF_only.txt"

        with open(outfile, 'wb') as src:
            pass

        with open(outfile, 'ab') as src:
            src.write(e_key)
            src.write(iv)
            src.write(ct)
        print("Successful! Output file is generated.")


    elif symEncType == 1:
        s='r'
        if te==1:
            s='rb'
        fi = open(inpfile, s)
        msg = fi.read()
        if te!=1:
            message = msg.encode()
        else:
            message = msg

        padder = ps.PKCS7(64).padder()
        message = padder.update(message)
        message += padder.finalize()

        key = os.urandom(24)
        backend = default_backend()
        iv = os.urandom(8)
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(message)

        recvpub = str(recv) + "_pub_" + str(keylen) + ".pem"

        with open(recvpub, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        e_key = public_key.encrypt(key,
                                   pa.OAEP(mgf=pa.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                label=None))

        al = sender + "_to_" + recv + "_enc_tdes_"+str(keylen)+"_CONF_only.txt"

        with open(outfile, 'wb') as src:
            pass
        with open(outfile, 'ab') as src:
            src.write(e_key)
            src.write(iv)
            src.write(ct)
        print("Successful! Output file is generated.")
        #print("writing to ", al)


def only_conf_DEC(sender, receiver,inpfile, outfile, symEncType, keylen):

    sender = sender.strip()
    recv = receiver.strip()
    rpri = str(recv) + "_pri_" + str(keylen) + ".pem"
    with open(rpri, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    if symEncType == 0:
        al = sender + "_to_" + recv + "_enc_aes_"+str(keylen)+"_CONF_only.txt"
        fipk = open(inpfile, 'rb')
        mall = fipk.read()
        if keylen == 2048:
            mpk = mall[0:256]
            miv = mall[256:272]
            mm  = mall[272:]
        elif keylen == 1024:
            mpk = mall[0:128]
            miv = mall[128:144]
            mm = mall[144:]
        plaintext = private_key.decrypt(mpk,
                                        pa.OAEP(
                                            mgf=pa.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        )
                                        )
        key = plaintext



        cipher = Cipher(algorithms.AES(key), modes.CBC(miv))
        decryptor = cipher.decryptor()
        dec = decryptor.update(mm) + decryptor.finalize()
        unpadder = ps.PKCS7(128).unpadder()
        dec = unpadder.update(dec)
        dec += unpadder.finalize()

        with open(outfile, 'wb') as src:
            src.write(dec)
        print("Decrypted!")

    elif symEncType == 1:
        fipk = open(inpfile, 'rb')
        mall = fipk.read()
        if keylen == 2048:
            mpk = mall[0:256]
            miv = mall[256:264]
            mm  = mall[264:]
        elif keylen == 1024:
            mpk = mall[0:128]
            miv = mall[128:136]
            mm = mall[136:]
        plaintext = private_key.decrypt(mpk,
                                        pa.OAEP(
                                            mgf=pa.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        )
                                        )
        #print("TDES Random key after decrypting:", plaintext)
        key = plaintext
        #print('dec key:',key)
        backend = default_backend()
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(miv), backend=backend)
        decryptor = cipher.decryptor()
        dec = decryptor.update(mm) + decryptor.finalize()

        unpadder = ps.PKCS7(64).unpadder()
        dec = unpadder.update(dec)
        dec += unpadder.finalize()

        #
        #print(dec)
        with open(outfile, 'wb') as src:
            src.write(dec)
        print("Decrypted!")



def only_AUIN_ENC(sender,receiver,inpfile, outfile, symEncType, hashtype, keylen,te):
    sender = sender.strip()
    recv = receiver.strip()
    rpri = str(sender) + "_pri_" + str(keylen) + ".pem"
    with open(rpri, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    s = 'r'
    if te == 1:
        s = 'rb'
    fi = open(inpfile, s)
    msg = fi.read()
    if te != 1:
        message = msg.encode()
    else:
        message = msg

    if hashtype == 1:
        digest = hashes.Hash(hashes.SHA3_512())
    else:
        digest = hashes.Hash(hashes.SHA512())
    digest.update(message)
    dig = digest.finalize()
#    print("enc digest for ",message,'is: ',dig)
    signature = private_key.sign(dig,
                                 pa.PSS(mgf=pa.MGF1(hashes.SHA256()), salt_length=pa.PSS.MAX_LENGTH),
                                 hashes.SHA256())


    with open(outfile,'wb') as src:
        pass
#    print(len(signature))
    with open(outfile, 'ab') as src:
        src.write(signature)
        src.write(message)
    print("Successful! Output file is generated.")


def only_AUIN_DEC(sender,receiver,inpfile, outfile, symEncType, hashtype, keylen):
    sender = sender.strip()
    recv = receiver.strip()
    recvpub = str(sender) + "_pub_" + str(keylen) + ".pem"

    with open(recvpub, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    fipk = open(inpfile, 'rb')
    mall = fipk.read()
    if keylen == 2048:
        mpk = mall[0:256]
        msg = mall[256:]
    elif keylen == 1024:
        mpk = mall[0:128]
        msg = mall[128:]


    if hashtype !=1:
        digest = hashes.Hash(hashes.SHA512())
    else:
        digest = hashes.Hash(hashes.SHA3_512())

    digest.update(msg)
    dig = digest.finalize()
#    print('calculating digest for msg:', msg, '\n')
#    print('digest is : ',dig)
    a = 0
#    print("\n\n")
    try:
        public_key.verify(mpk, dig,
                          pa.PSS(mgf=pa.MGF1(hashes.SHA256()), salt_length=pa.PSS.MAX_LENGTH),
                          hashes.SHA256())
    except Exception as e:
        print("signature not valid")
        a = 1
    if (a != 1):
        print("Signature valid!")

def COAI_ENC(sender,receiver,inpfile, outfile, symEncType, hashtype, keylen):

    only_AUIN_ENC(sender,receiver,inpfile, 'tempout.txt', symEncType, hashtype, keylen,1)
    only_conf_ENC(sender, receiver, 'tempout.txt', outfile, symEncType, keylen,1)

def COAI_DEC(sender,receiver,inpfile, outfile, symEncType, hashtype, keylen):
    only_conf_DEC(sender, receiver, inpfile, 'tempout1.txt', symEncType, keylen)
    only_AUIN_DEC(sender, receiver, 'tempout1.txt', outfile, symEncType, hashtype, keylen)

if __name__ == '__main__':
    if sys.argv[1] == "CreateKeys":
        l = int(sys.argv[3])
        file1 = open(sys.argv[2], 'r')
        count = 0
        while True:
            count += 1
            user = file1.readline()
            if not user:
                break
            print("creating RSA keys for user:", count, ":", user.strip(), " keylength:", l)
            RSAkeygen(user.strip(), l)
        file1.close()

    elif sys.argv[1] == "CreateMail":
        if sys.argv[2] == "CONF":
            t1 = 0
            keylen = int(sys.argv[9])
            if sys.argv[8] == "des-ede3-cbc":
                t1 = 1
            only_conf_ENC(sys.argv[3], sys.argv[4], sys.argv[5],sys.argv[6] ,t1, keylen,0)

        elif sys.argv[2] == "AUIN":
            t = 0
            hashtype = 0
            keylen = int(sys.argv[9])
            if sys.argv[8] == "des-ede3-cbc":
                t = 1
            if sys.argv[7] == "sha3-512":
                hashtype = 1
            only_AUIN_ENC(sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], t, hashtype, keylen,1)

        elif sys.argv[2] == "COAI":
            t = 0
            hashtype = 0
            keylen = int(sys.argv[9])
            if sys.argv[8] == "des-ede3-cbc":
                t = 1
            if sys.argv[7] == "sha3-512":
                hashtype = 1
            COAI_ENC(sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], t, hashtype, keylen)




    elif sys.argv[1] == "ReadMail":
        if sys.argv[2] == "CONF":
            t = 0
            keylen = int(sys.argv[9])
            if sys.argv[8] == "des-ede3-cbc":
                t = 1
            only_conf_DEC(sys.argv[3], sys.argv[4],sys.argv[5],sys.argv[6], t, keylen)

        elif sys.argv[2] == "AUIN":
            t = 0
            hashtype = 0
            keylen = int(sys.argv[9])
            if sys.argv[8] == "des-ede3-cbc":
                t = 1
            if sys.argv[7] == "sha3-512":
                hashtype = 1
            only_AUIN_DEC(sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], t, hashtype, keylen)


        elif sys.argv[2] == "COAI":
            t = 0
            hashtype = 0
            keylen = int(sys.argv[9])
            if sys.argv[8] == "des-ede3-cbc":
                t = 1
            if sys.argv[7] == "sha3-512":
                hashtype = 1
            COAI_DEC(sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], t, hashtype, keylen)

    else:
        print("wrong input!")
