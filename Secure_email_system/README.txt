Programming Assignment 2:
CS20M030: KOLAN NIKSHITH REDDY
--------------------------------------------------------
BELOW ARE THE PYTHON COMMANDS TO EXECUTE THE PROGRAM.
All The test cases for key length: 1024,2048, Digest: Sha512, Sha3-512, Encryption algorithms: AES-256-cbc, TripleDES are verified properly

Message length can be of any length, Padding is also properly implemented!
---------------------------------------------------------


After compiling the program, one can run it to
i) Create keys using the command
    
    ./lab3 CreateKeys UserNameListFile RSAKeySize
    
    where,
        UserNameListFile has list of all users 
        RSAKeySize is usually either 1024 or 2048

ii) Create security enhanced mail using the command
    
    ./lab3 CreateMail SecType Sender Receiver EmailInputFile \
    EmailOutputFile DigestAlg EncryAlg RSAKeySize
    
    where, 
        SecType is one of CONF, AUIN, COAI depending on security requirement
        Sender/Receiver are sender and recipient of this message.
        EmailInputFile contains the input plain-text file. 
        EmailOutputFile contains the output of the encryption algorithms. 
        DigestAlg is one of: sha512, sha3-512
        EncryAlg is one of: des-ede3-cbc, aes-256-cbc

iii) Read mails generated in above fashion using
    ./lab3 ReadMail SecType Sender Receiver SecureInputFile \
    PlainTextOutputFile DigestAlg EncryAlg RSAKeySize

    where,
        parameters have meaning similar to above

--------------------------------------------------------------------------------------

To the best of developer's knowledge, this application works perfectly fine

***********************************************************************************
CASE 1: ONLY CONFIDENTIALITY (CONF):
python main.py CreateMail CONF alice bob input.txt out.txt sha512 des-ede3-cbc 2048
python main.py ReadMail CONF alice bob out.txt out1.txt sha512 des-ede3-cbc 2048

python main.py CreateMail CONF alice bob input.txt out.txt sha512 des-ede3-cbc 1024
python main.py ReadMail CONF alice bob out.txt out1.txt sha512 des-ede3-cbc 1024

python main.py CreateMail CONF alice bob input.txt out.txt sha512 aes-256-cbc 2048
python main.py ReadMail CONF alice bob out.txt out1.txt sha512 aes-256-cbc 2048

python main.py CreateMail CONF alice bob input.txt out.txt sha512 aes-256-cbc 1024
python main.py ReadMail CONF alice bob out.txt out1.txt sha512 aes-256-cbc 1024

python main.py CreateMail CONF alice bob input.txt out.txt sha3-512 des-ede3-cbc 2048
python main.py ReadMail CONF alice bob out.txt out1.txt sha3-512 des-ede3-cbc 2048

python main.py CreateMail CONF alice bob input.txt out.txt sha3-512 des-ede3-cbc 1024
python main.py ReadMail CONF alice bob out.txt out1.txt sha3-512 des-ede3-cbc 1024

python main.py CreateMail CONF alice bob input.txt out.txt sha3-512 aes-256-cbc 2048
python main.py ReadMail CONF alice bob out.txt out1.txt sha3-512 aes-256-cbc 2048

python main.py CreateMail CONF alice bob input.txt out.txt sha3-512 aes-256-cbc 1024
python main.py ReadMail CONF alice bob out.txt out1.txt sha3-512 aes-256-cbc 1024

*****************************END OF CONF**********************




***************************START OF AUIN***********************
python main.py CreateMail AUIN alice bob input.txt out.txt sha512 des-ede3-cbc 2048
python main.py ReadMail AUIN alice bob out.txt out1.txt sha512 des-ede3-cbc 2048

python main.py CreateMail AUIN alice bob input.txt out.txt sha512 des-ede3-cbc 1024
python main.py ReadMail AUIN alice bob out.txt out1.txt sha512 des-ede3-cbc 1024

python main.py CreateMail AUIN alice bob input.txt out.txt sha512 aes-256-cbc 2048
python main.py ReadMail AUIN alice bob out.txt out1.txt sha512 aes-256-cbc 2048

python main.py CreateMail AUIN alice bob input.txt out.txt sha512 aes-256-cbc 1024
python main.py ReadMail AUIN alice bob out.txt out1.txt sha512 aes-256-cbc 1024

python main.py CreateMail AUIN alice bob input.txt out.txt sha3-512 des-ede3-cbc 2048
python main.py ReadMail AUIN alice bob out.txt out1.txt sha3-512 des-ede3-cbc 2048

python main.py CreateMail AUIN alice bob input.txt out.txt sha3-512 des-ede3-cbc 1024
python main.py ReadMail AUIN alice bob out.txt out1.txt sha3-512 des-ede3-cbc 1024

python main.py CreateMail AUIN alice bob input.txt out.txt sha3-512 aes-256-cbc 2048
python main.py ReadMail AUIN alice bob out.txt out1.txt sha3-512 aes-256-cbc 2048

python main.py CreateMail AUIN alice bob input.txt out.txt sha3-512 aes-256-cbc 1024
python main.py ReadMail AUIN alice bob out.txt out1.txt sha3-512 aes-256-cbc 1024



*****************************END OF AUIN**********************



***************************START OF COAI***********************
python main.py CreateMail COAI alice bob input.txt out.txt sha512 des-ede3-cbc 2048
python main.py ReadMail COAI alice bob out.txt out1.txt sha512 des-ede3-cbc 2048

python main.py CreateMail COAI alice bob input.txt out.txt sha512 des-ede3-cbc 1024
python main.py ReadMail COAI alice bob out.txt out1.txt sha512 des-ede3-cbc 1024

python main.py CreateMail COAI alice bob input.txt out.txt sha512 aes-256-cbc 2048
python main.py ReadMail COAI alice bob out.txt out1.txt sha512 aes-256-cbc 2048

python main.py CreateMail COAI alice bob input.txt out.txt sha512 aes-256-cbc 1024
python main.py ReadMail COAI alice bob out.txt out1.txt sha512 aes-256-cbc 1024

python main.py CreateMail COAI alice bob input.txt out.txt sha3-512 des-ede3-cbc 2048
python main.py ReadMail COAI alice bob out.txt out1.txt sha3-512 des-ede3-cbc 2048

python main.py CreateMail COAI alice bob input.txt out.txt sha3-512 des-ede3-cbc 1024
python main.py ReadMail COAI alice bob out.txt out1.txt sha3-512 des-ede3-cbc 1024

python main.py CreateMail COAI alice bob input.txt out.txt sha3-512 aes-256-cbc 2048
python main.py ReadMail COAI alice bob out.txt out1.txt sha3-512 aes-256-cbc 2048

python main.py CreateMail COAI alice bob input.txt out.txt sha3-512 aes-256-cbc 1024
python main.py ReadMail COAI alice bob out.txt out1.txt sha3-512 aes-256-cbc 1024



*****************************END OF COAI**********************