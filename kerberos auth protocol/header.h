
int Base64Encode( char** b64text,const unsigned char* buffer, size_t length) 
{   BUF_MEM *bufferPtr;
    BIO *bioptr, *b64ptr;

    b64ptr = BIO_new(BIO_f_base64());
    bioptr = BIO_new(BIO_s_mem());
    bioptr = BIO_push(b64ptr, bioptr);

    BIO_set_flags(bioptr, BIO_FLAGS_BASE64_NO_NL); 
    BIO_write(bioptr, buffer, length);
    BIO_flush(bioptr);
    BIO_get_mem_ptr(bioptr, &bufferPtr);
    BIO_set_close(bioptr, BIO_NOCLOSE);
    BIO_free_all(bioptr);

    *b64text=(*bufferPtr).data;

    return 0; 
}


size_t getfinallen(size_t temp1, size_t temp2 ){
    return (temp1*3)/4 -temp2;
}
int getpadlen(const char* temp1, size_t temp2){
    int i=0;
    if (temp1[temp2-1] == '=') 
        i = 1;
    if (temp1[temp2-1] == '=' && temp1[temp2-2] == '=') 
        i = 2;
    return i;
}

size_t callength(const char* b64user) { 
    size_t    p = 0;
    size_t len = strlen(b64user);
    int i=0;
     i =getpadlen(b64user, len);
     switch(i){
        case 1: p = 1;break;
        case 2: p = 2;break;
    }

    return getfinallen(len, p);
}



int Base64Decode( unsigned char** buffer,char* b64message, size_t* length) 
{   BIO *bioptr, *b64ptr;

    int decodeLen = callength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bioptr = BIO_new_mem_buf(b64message, -1);
    b64ptr = BIO_new(BIO_f_base64());
    bioptr = BIO_push(b64ptr, bioptr);

    BIO_set_flags(bioptr, BIO_FLAGS_BASE64_NO_NL); 
    *length = BIO_read(bioptr, *buffer, strlen(b64message));
    assert(*length == decodeLen); 
    BIO_free_all(bioptr);
    return 0; 
}

int encryptionfunction(char *pt, unsigned char *key, unsigned char *iv, char ct_base64[]){
        unsigned char ct[1024];
    int ct_len=0, len,ct_len1;
    EVP_CIPHER_CTX *ctx;
    int pt_len = strlen ((char *)pt);
    if(!(ctx = EVP_CIPHER_CTX_new())){ ERR_print_errors_fp(stderr);abort(); }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)){ ERR_print_errors_fp(stderr); abort(); }

    if(1 != EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len)) { ERR_print_errors_fp(stderr); abort(); }

    ct_len1 = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ct + len, &len)){ ERR_print_errors_fp(stderr); abort(); }
    ct_len1 = ct_len1+ len;
    EVP_CIPHER_CTX_free(ctx);
    ct_len = ct_len1;
    char *ct_base;
    
    Base64Encode( &ct_base, ct, strlen(ct));
    strcpy(ct_base64,ct_base);

    return ct_len;
}

void decryptionfunction(  unsigned char *iv,unsigned char *key, int length,char * ct_base64, unsigned char dt[]){
    unsigned char* ct;
    size_t test;
    Base64Decode( &ct, ct_base64, &test);

    int dt_len=0;
    int ct_len = length;

    EVP_CIPHER_CTX *ctx;
    int len, pt_len;

    if(!(ctx = EVP_CIPHER_CTX_new())){ERR_print_errors_fp(stderr);abort();}

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)){ERR_print_errors_fp(stderr);abort();}

    if(1 != EVP_DecryptUpdate(ctx, dt, &len, ct, ct_len)){ERR_print_errors_fp(stderr); abort();}

    pt_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, dt + len, &len)){ ERR_print_errors_fp(stderr); abort();}
    pt_len = pt_len + len;
    EVP_CIPHER_CTX_free(ctx);
    dt_len =  pt_len;
    dt[dt_len] = '\0';
}




