#include <stdio.h>
#include <unistd.h>
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <time.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <assert.h>
#include <openssl/aes.h>
#include <arpa/inet.h>
#include "header.h"

int Nonce = 1000;
unsigned char *iv;
int registrationfunction(char buffer[], int cSocket, char *user, char * cip, char *cport, unsigned char *pwd)
{
    char responsecode[5], ip[16],cportnum[8],cm[12],cuser[12];
    strcpy(buffer,"|");
    strcpy(responsecode,"301");
    strcat(buffer,responsecode);
    strcat(buffer,"|");    
    strcpy(ip,cip);
    strcat(buffer,ip);
    strcat(buffer,"|");
    strcpy(cportnum,cport);
    strcat(buffer,cportnum);
    strcat(buffer,"|");
    strcpy(cm,pwd);
    strcat(buffer,cm);
    strcat(buffer,"|");
    strcpy(cuser,user);
    strcat(buffer,cuser);
    strcat(buffer,"|");

    //send registration message to KDC
    write(cSocket,buffer,1024); 

    //receive confirmation message for registration from KDC
    read(cSocket,buffer,1024);


    printf("%s registered in KDC\n", user);
    return 1;
}


void requestKey(char buffer[], int cSocket, char *ip, char *user, char *ouser, unsigned char *key, unsigned char *iv)
{
    
    char length[10];
    char ct_base64[1024], code[5],message[1024], identitya[10], identityb[10], nonce1[10];
    int ct_len;
    strcpy(buffer,"|");
    strcpy(code,"305");
    strcat(buffer,code);
    strcat(buffer,"|");

    strcpy(identitya,user);
    strcpy(message,identitya);
    strcat(message,"$");
    strcpy(identityb,ouser);
    strcat(message,identityb);
    strcat(message,"$");
    sprintf(nonce1,"%d",Nonce);
    Nonce = Nonce+1; 
    strcat(message,nonce1);


    ct_len = encryptionfunction(message,key,iv,ct_base64);
    strcat(buffer,ct_base64);
    strcat(buffer,"|");
    sprintf(length,"%d",ct_len);
    strcat(buffer,length);
    strcat(buffer,"|");
    strcat(buffer,identitya);
    strcat(buffer,"|");
    write(cSocket,buffer,1024);
    printf("Sent key request message with code 305 message to KDC\n");
    read(cSocket,buffer,1024);
    printf("Received Response Code 306 from KDC\n");
    printf("%s got the key of %s from KDC\n", user, ouser);
 
}

void client(char *user, char *ouser, char *ip, char *kip, int kport, unsigned char *iv)
{
    int cSocket;
    char buffer[1024];
    struct sockaddr_in sAddr;
    sAddr.sin_addr.s_addr = inet_addr(kip);
    sAddr.sin_port = htons(kport);
    sAddr.sin_family = AF_INET;
    memset(sAddr.sin_zero, '\0', sizeof sAddr.sin_zero);  

    cSocket = socket(PF_INET, SOCK_STREAM, 0);
   
    socklen_t addr_size = sizeof sAddr;

    connect(cSocket, (struct sockaddr *) &sAddr, addr_size);
    char * cip = "127.0.0.1";
    char *cport = "7000";

    unsigned char *pwd = "qazxswqazxswqazx";

    int value = registrationfunction(buffer, cSocket, user, cip, cport, pwd);

    sleep(1);

    requestKey(buffer, cSocket, ip, user, ouser, pwd, iv);

    close(cSocket);
}

void server(char *user, char *outenc, char *of, char *kip, int kport, unsigned char *iv)
{
    int cSocket;
    char buffer[1024];
    struct sockaddr_in sAddr;
    sAddr.sin_addr.s_addr = inet_addr(kip);
    sAddr.sin_family = AF_INET;
    sAddr.sin_port = htons(kport);

    memset(sAddr.sin_zero, '\0', sizeof sAddr.sin_zero);  
   
    socklen_t  addr_size = sizeof sAddr;
    cSocket = socket(PF_INET, SOCK_STREAM, 0);

    connect(cSocket, (struct sockaddr *) &sAddr, addr_size);  

    char *cip = "127.0.0.1";
    char *cport = "6000";

    unsigned char *pwd = "qwertyuiopasdfgh";

    int value = registrationfunction(buffer, cSocket, user, cip, cport, pwd);

    sleep(1);

    close(cSocket);
}

int main(int argc, char *argv[])
{
    char *user, *SeRe, *ouser, *ip, *kip, *outenc;
    int opt, kport;

    while((opt = getopt(argc, argv, ":n:m:o:i:a:p:s:")) != -1){
        switch(opt) {
            case 'a':
                kip = optarg;
                printf("kerberos distribution center ip = %s\n", kip);
                break;
            case 'i':
                ip = optarg;
                printf("input file given = %s\n", ip);
                break;
            case 'm':
                SeRe = optarg;
                printf("Type = %s\n", SeRe);
                break;
            case 'n':
                user = optarg;
                printf("name  of the user= %s\n", user);
                break;
            case 'o':
                ouser = optarg;
                printf("other user name = %s\n", ouser);
                break;
            
            
            case 'p':
                kport = atoi(optarg);
                printf("kerberos distribution center port = %d\n", kport);
                break;
            case 's':
                outenc = optarg;
                printf("outenc = %s\n", outenc);
                break;
                
            case ':':
                printf("option needs a value. please check\n");
                break;
            case '?':
                printf("unknown option given. please check: %c\n", optopt);
                break;
        }
    }

    iv = (unsigned char *)malloc(AES_BLOCK_SIZE*sizeof(unsigned char));
    memset(iv, 0x00, AES_BLOCK_SIZE);
    int tr = 0;
    int ts = 0;
    tr = strcmp(SeRe,"R") == 0;
    ts = strcmp(SeRe,"S") == 0;
    if(ts)
        client(user,ouser,ip,kip,kport,iv);
    else if(tr)
        server(user,outenc,ouser,kip,kport,iv);
    else
        printf("invalid input given. please check.\n");

    return 0;
}
