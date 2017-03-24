#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>
#include <string.h>

#include "encl1.h"
#include "encl1_t.h"  /* print_string */

#include <sgx_tcrypto.h>
#include <sgx_trts.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_encl1_sample(buf);
}

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

const unsigned char gcm_key[16]= {
        0xee,0xbc,0x1f,0x57,0x48,0x7f,0x51,0x92,0x1c,0x04,0x65,0x66,
        0x5f,0x8a,0xe6,0xd1
};
const unsigned char gcm_iv[12] = {
        0x99,0xaa,0x3e,0x68,0xed,0x81,0x73,0xa0,0xee,0xd0,0x66,0x84
};

void encl1_AES_GCM_encrypt(char *p_src,uint32_t src_len,char *p_des,uint32_t des_len, sgx_aes_gcm_128bit_tag_t *p_mac)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_aes_gcm_128bit_key_t *p_key;
    uint8_t *p_iv;
    uint32_t iv_len;
    uint8_t *p_aad;
    uint32_t aad_len;

    p_key = gcm_key;
//    p_des = (char *)malloc(sizeof(char)*1000);
    p_iv = gcm_iv;
    iv_len = 12;
    p_aad = NULL;
    aad_len = 0;
//    p_mac = (sgx_aes_gcm_128bit_tag_t *)malloc(sizeof(sgx_aes_gcm_128bit_tag_t)*1000);

    ret = sgx_rijndael128GCM_encrypt(p_key, p_src, src_len, p_des, p_iv, iv_len, p_aad, aad_len, p_mac);

    if (ret == SGX_SUCCESS){
       printf("AES GCM encryption success!\n");
       printf("Plain txt: %s\n", p_src);
       printf("Encrypted txt: %s\n", p_des);
       printf("MAC: %s\n", p_mac);
    } 
    else{
       print_error_message(ret);
    }

//    char *p_plain;
//    p_plain = (char *)malloc(sizeof(char)*1000);
//    ret = sgx_rijndael128GCM_decrypt(p_key, p_des, src_len, p_plain, p_iv, iv_len, p_aad, aad_len, p_mac);
//
//    if (ret == SGX_SUCCESS){
//       printf("AES GCM decryption success!\n");
//       printf("Encrypted txt: %s\n", p_des);
//       printf("Decrypted txt: %s\n", p_plain);
//       printf("MAC: %s\n", p_mac);
//    }
//    else{
//       print_error_message(ret);
//    }
    printf("enclave gcm encrypt!\n");
}

void encl1_AES_GCM_decrypt(char *p_src,uint32_t src_len,char *p_des,uint32_t des_len, sgx_aes_gcm_128bit_tag_t *p_mac)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_aes_gcm_128bit_key_t *p_key;
    uint8_t *p_iv;
    uint32_t iv_len;
    uint8_t *p_aad;
    uint32_t aad_len;

    p_key = gcm_key;
//    p_des = (char *)malloc(sizeof(char)*1000);
    p_iv = gcm_iv;
    iv_len = 12;
    p_aad = NULL;
    aad_len = 0;
//    p_mac = (sgx_aes_gcm_128bit_tag_t *)malloc(sizeof(sgx_aes_gcm_128bit_tag_t)*1000);
    printf("src_len:%d\n",src_len);
    printf("p_src:%s\n",p_src);
    printf("p_mac:%s\n",p_mac);

    ret = sgx_rijndael128GCM_decrypt(p_key, p_src, src_len, p_des, p_iv, iv_len, p_aad, aad_len, p_mac);    

    if (ret == SGX_SUCCESS){
       printf("AES GCM decryption success!\n");
       printf("Encrypted txt: %s\n", p_src);
       printf("Decrypted txt: %s\n", p_des);
       printf("MAC: %s\n", p_mac);
    }
    else{
       print_error_message(ret);
    }
    printf("enclave GCM decrypt\n");
}

void ecall_encl1_update_operation(char *key, int *flag, int* vlen, char *value, char *value_update, int tlen)
{
    char *key_plain, *value_plain, *value_enc, *key_enc, *update_enc;
    sgx_aes_gcm_128bit_tag_t *p_mac;
    printf("value in enclave:\n");
    printf("len:%d, key:%s\n",strlen(key),key);
    printf("len:%d, value:%s\n",strlen(value),value);
    printf("len:%d, value_update:%s\n",strlen(value_update),value_update);
    key_enc = (unsigned char *)malloc(sizeof(unsigned char)*500);
    key_plain = (unsigned char *)malloc(sizeof(unsigned char)*500);
    value_plain = (unsigned char *)malloc(sizeof(unsigned char)*1000);
    value_enc = (unsigned char *)malloc(sizeof(unsigned char)*1000);
    update_enc =  (unsigned char *)malloc(sizeof(unsigned char)*1000);
    p_mac = (sgx_aes_gcm_128bit_tag_t *)malloc(sizeof(sgx_aes_gcm_128bit_tag_t));
   
    //decrypt key
    printf("Begin copy p_mac\n");
    strncpy(p_mac, key, 16);
    printf("End copy p_mac\n");
    strncpy(key_enc,key+16,strlen(key)-16);
    encl1_AES_GCM_decrypt(key_enc, strlen(key_enc), key_plain, strlen(key_enc), p_mac);
    printf("decrypted key:%s\n",key_plain);
    printf("strlen(key):%d\n",strlen(key_plain));
    
    //decrypt value 
    strncpy(p_mac, value, 16);
    strncpy(value_enc,value+16,strlen(value)-16-2);
    encl1_AES_GCM_decrypt(value_enc, strlen(value_enc), value_plain, strlen(value_enc), p_mac);
    printf("decrypted value:%s\n",value_plain+24);
    printf("strlen(value):%d\n",strlen(value_plain+24));
    memset(value,0,*vlen);   
    strncpy(value,value_plain,strlen(value_plain)); 
    
  
    //decrypt value_update
    strncpy(p_mac, value_update, 16);
    strncpy(update_enc,value_update+16,strlen(value_update)-16-2);
    encl1_AES_GCM_decrypt(update_enc, strlen(update_enc), value_plain, strlen(update_enc), p_mac);
    printf("decrypted value:%s\n",value_plain+48);
    printf("strlen(value):%d\n",strlen(value_plain+48));
    strncat(value,value_plain+48,strlen(value_plain+48));
    printf("cyx strlen(value):%d\n",strlen(value));   
    encl1_AES_GCM_encrypt(value, strlen(value), value_enc, strlen(value), p_mac);
    printf("appended value:%s\n",value);
    printf("cyx enc strlen(value_enc):%d\n",strlen(value_enc));
    memset(value,0,strlen(value_enc)+16+2);
    strncpy(value,p_mac,16);
    strncpy(value+16,value_enc,strlen(value_enc));
    strcat(value,"\r\n");
    printf("encrypted value:%s\n",value);
//    encl1_AES_GCM_decrypt(value+16,strlen(value+16), value_plain, strlen(value+16), p_mac);
//    printf("decrypted value:%s\n",value_plain);
    printf("strlen(value):%d\n",strlen(value));   
    printf("enclave update operations!\n");
}

void ecall_encl1_AES_GCM_decrypt(const char *p_src, uint32_t src_len, char *p_dec, uint32_t *dec_len)
{
	const unsigned char gcm_key[16]= {
	        0xee,0xbc,0x1f,0x57,0x48,0x7f,0x51,0x92,0x1c,0x04,0x65,0x66,
	        0x5f,0x8a,0xe6,0xd1
	};
	const unsigned char gcm_iv[12] = {
	        0x99,0xaa,0x3e,0x68,0xed,0x81,0x73,0xa0,0xee,0xd0,0x66,0x84
	};

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	sgx_aes_gcm_128bit_key_t *p_key;
	uint8_t *pest_src = "my first sgx!";
//	uint32_t src_len;
	uint8_t *p_dst;
	uint8_t *p_iv;
	uint32_t iv_len;
	uint8_t *p_aad;
	uint32_t aad_len;
	sgx_aes_gcm_128bit_tag_t *p_out_mac;
    uint8_t *p_decrypt;

    p_key = gcm_key;
//    src_len = strlen(p_src);
    p_dst = (uint8_t *)malloc(sizeof(uint8_t)*1000);
    p_iv = gcm_iv;
    iv_len = 12;
    p_aad = NULL;
    aad_len = 0;
    p_out_mac = (sgx_aes_gcm_128bit_tag_t *)malloc(sizeof(sgx_aes_gcm_128bit_tag_t)*1000);

    ret = sgx_rijndael128GCM_encrypt(p_key, p_src, strlen(p_src), p_dst, p_iv, iv_len, p_aad, aad_len, p_out_mac);

    if (ret == SGX_SUCCESS){
       printf("AES GCM encryption success!\n");
       printf("Plain txt: %s\n", p_src);
       printf("Encrypted txt: %s\n", p_dst);
       printf("MAC: %s\n", p_out_mac);
    }
    printf("p_src:%s\n",p_src);
    printf("src_len:%d\n",src_len);
    printf("strlen(p_src):%d\n",strlen(p_src));
    p_decrypt = (uint8_t *)malloc(sizeof(uint8_t)*1000);
    ret = sgx_rijndael128GCM_decrypt(p_key, p_dst, strlen(p_dst), p_decrypt, p_iv, iv_len, p_aad, aad_len, p_out_mac);
//    p_dec = p_decrypt;
    *dec_len = strlen(p_decrypt);
    if (ret == SGX_SUCCESS){
    	printf("transfer p_src: %s\n",p_dst);
    	printf("AES GCM decryption success!\n");
    	printf("Decrypted txt: %s\n", p_decrypt);
    	printf("strlen(p_dec):%d\n",strlen(p_decrypt));
    	printf("MAC: %s\n", p_out_mac);
    }
    else{
    	print_error_message(ret);
    }
}

