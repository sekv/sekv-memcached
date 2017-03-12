#ifndef ENCL1_T_H__
#define ENCL1_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void ecall_encl1_AES_GCM_decrypt(const char* p_src, uint32_t src_len, char* p_dec, uint32_t* dec_len);
void ecall_encl1_update_operation(char* key, int* flag, int* vlen, char* value, char* value_update);

sgx_status_t SGX_CDECL ocall_encl1_sample(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
