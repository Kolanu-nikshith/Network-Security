#include<stdio.h>
#include<unistd.h>
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
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <arpa/inet.h>
#include "header.h"

char *cIpAddr[1024], *cPortNum[1024], *cMasterKey[1024], *cName[1024];
int tempreg;
char* temp = "abcdeabcdeabcdef";


int searchfor( char* temp1,char **temp2, int n) {

    int i=0;int j=0;
    while(i<n){
        if(strcmp(temp2[i], temp1) == 0) {
            j=1;
        }
        if (j==1){
            return i;
        }
        else {
            i++;
        }
    }

    return -1;
}


unsigned char* getiv(){
    return (unsigned char *)malloc(AES_BLOCK_SIZE*sizeof(unsigned char));
}
unsigned char* getkey(){
    return "asdfgasdfgasdfgh";
}
char* getmem(char* temp1){
    return  (char*)malloc(strlen(temp1));
}
void rmsg( char* outfile,  int newsocket,char* port,char* passwdfile) {
    
    unsigned char *kdc_key = getkey();
    unsigned char *iv = getiv();
    memset(iv, 0x00, AES_BLOCK_SIZE);
    char buffer[1024];
    read(newsocket, buffer, 1024);


    char * token = strtok(buffer, "|");

    int temptoken_301 = atoi(token) == 301;
    int temptoken_305 = atoi(token) == 305;

    if(temptoken_301) {
        puts("\n*** User Registration Started. Code : 301 received from client***\n");
        char* registration[5];
        int i = 0;
        while(token != NULL) {
            registration[i] = token;
            i++;
            token = strtok(NULL, "|");
        }
        int temp_index = searchfor(registration[4],cName,  tempreg);
        if(temp_index == -1) {

            cName[tempreg] =getmem(registration[4]);
            cMasterKey[tempreg] = getmem(registration[3]); 
            cPortNum[tempreg] = getmem(registration[2]);
            cIpAddr[tempreg] = getmem(registration[1]);
            
            strcpy(cName[tempreg], registration[4]);
            strcpy(cMasterKey[tempreg], registration[3]);
            strcpy(cPortNum[tempreg], registration[2]);
            strcpy(cIpAddr[tempreg], registration[1]);
            tempreg++;
        }
        else {
            cMasterKey[temp_index] = registration[3];
        }

         
        
        int ct_len;
        char ct_base64[1024];

        ct_len = encryptionfunction(registration[3],kdc_key,iv,ct_base64);

        FILE *ptemp = fopen(passwdfile, "a");
        fprintf(ptemp, ":%s:%s:%s:%s:\n", registration[4], registration[1], registration[2], ct_base64);
        fflush(ptemp);
        fclose(ptemp);

        strcpy(buffer, "|302|");
        strcat(buffer, registration[4]);
        strcat(buffer, "|");

        write(newsocket, buffer, 1024);

        printf("%s successfully registered\n", registration[4]);
        printf("Sending response code 302 to client\n");

    }
    else if(temptoken_305) {
        puts("key request message with code 305 received. Processing...\n");

        char* registration[4];
        int i = 0;
        while(token != NULL) {
            registration[i] = token;
            i++;
            token = strtok(NULL, "|");
        }

        char identitya[20];
        strcpy(identitya,registration[3]);

        int iA = searchfor(identitya,cName, tempreg);

        int len = atoi(registration[2]);

        unsigned char key[16];
        strcpy(key, cMasterKey[iA]);
        
        unsigned char decrypted[1024];
        decryptionfunction(iv,key,len,registration[1],decrypted);
        char *stemp[3];

        char *token2 = strtok(decrypted, "$");
        int l = 0;
        while(token2 != NULL) {
            stemp[l++] = token2;
            token2 = strtok(NULL, "$");
        }

        char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        char sharedKey[16];
        srand(time(0));
        for(int j = 0; j < 16; j++) {
            sharedKey[j] = charset[rand() % 62];
        }
        sharedKey[15] = '\0';
        int iB = searchfor(stemp[1],cName, tempreg);

        char str2[1024];
        strncpy(str2, sharedKey, 16);
        strcat(str2,"$");
        strcat(str2, stemp[0]);
        strcat(str2,"$");
        strcat(str2, stemp[1]);
        strcat(str2,"$");
        strcat(str2, stemp[2]);
        strcat(str2,"$");
        strcat(str2, cIpAddr[iA]);
        strcat(str2,"$");
        strcat(str2, cPortNum[iA]);


        unsigned char *key_b = "qwertyqwertyqwer";
        int ct_len;

        char ct_base64[1024];

        ct_len = encryptionfunction(str2,key_b,iv,ct_base64);
       

        strcpy(str2,ct_base64);

        char length[10];
        sprintf(length,"%d",ct_len);

        strcat(str2,"$");
        strcat(str2,length);

        char str1[1024];
        strncpy(str1, sharedKey, 16);
        strcat(str1,"$");
        strcat(str1, stemp[0]);
        strcat(str1,"$");
        strcat(str1, stemp[1]);
        strcat(str1,"$");
        strcat(str1, stemp[2]);
        strcat(str1,"$");
        strcat(str1, cIpAddr[iB]);
        strcat(str1,"$");
        strcat(str1, cPortNum[iB]);
        strcat(str1,"$");
        strcat(str1, str2); 

        strcpy(buffer, "|306|");


        ct_len = encryptionfunction(str1,key,iv,ct_base64);
       
        strcpy(str1,ct_base64);
        sprintf(length,"%d",ct_len);

        strcat(buffer, str1); 
        strcat(buffer, "|");

        strcat(buffer,length);
        strcat(buffer,"|");

        write(newsocket, buffer, 1024);
        printf("Response and Key has been generated and sent to client %s  with code 306.  \n", identitya);
 
    }

    return;

}

int main(int argc, char* argv[]) {
    int opt;
    char *p, *of, *pf;

    while((opt = getopt(argc, argv, ":p:o:f:")) != -1) {
        switch(opt) {
            case 'p':
                p = optarg;
                printf("Kerberos Distribution center runs on port number = %s\n", p);
                break;
            case 'o':
                of = optarg;
                printf("output file given = %s\n", of);
                break;
            case 'f':
                pf = optarg;
                printf("password file = %s\n", pf);
                break;
            case ':':
                printf("value need to be given for the option\n");
                break;
            case '?':
                printf("unknown option given. Please check: %c\n", optopt);
                break;
        }
    }

    FILE* o = fopen(of, "w");

    int sid, s2, s1;
    struct sockaddr_in sAddr;
    struct sockaddr_storage sStorage;
    socklen_t addr_size;

    sid = socket(AF_INET, SOCK_STREAM, 0);
    if(sid == -1) {
        fprintf(o, "socket creation failed...\n");
        exit(0);
    }
    else {
        fprintf(o, "socket successfully created...\n");
    }
    
    sAddr.sin_family = AF_INET;
    sAddr.sin_port = htons(atoi(p));
    sAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    memset(sAddr.sin_zero, '\0', sizeof sAddr.sin_zero);

    if((bind(sid, (struct sockaddr *) &sAddr, sizeof(sAddr))) != 0) {
        fprintf(o, "socket binding failed.Please try again.\n");
        exit(0);
    }
    else {
        fprintf(o, "Socket binded successfully.status OK\n");
    }

    if (listen(sid, 5) != 0) {
        fprintf(o, "Listen failed.Please check again.\n");
        exit(0);
    }
    else {
        fprintf(o, "Server started listening. Status OK\n");
    }

    addr_size = sizeof sStorage;

    s1 = accept(sid, (struct sockaddr *) &sStorage, &addr_size);
    if(s1 < 0) {
        fprintf(o, "server  acceptance failed. Please check again.\n");
        exit(0);
    }
    else {
        fprintf(o, "server accepted the client successfully.\n");
    }

    s2 = accept(sid, (struct sockaddr *) &sStorage, &addr_size);
    if(s2 < 0) {
        fprintf(o, "server acceptance failed. Please check again.\n");
        exit(0);
    }
    else {
        fprintf(o, "server accepted the client successfully.\n");
    }

    fclose(o);

    rmsg( of, s1,p,pf);
    rmsg( of, s2,p,pf);
    rmsg( of, s1,p,pf);

    close(s1);
    close(s2);

    return 0;
}