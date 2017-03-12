#include "encl1_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_encl1_AES_GCM_decrypt_t {
	char* ms_p_src;
	uint32_t ms_src_len;
	char* ms_p_dec;
	uint32_t* ms_dec_len;
} ms_ecall_encl1_AES_GCM_decrypt_t;

typedef struct ms_ecall_encl1_update_operation_t {
	char* ms_key;
	int* ms_flag;
	int* ms_vlen;
	char* ms_value;
	char* ms_value_update;
} ms_ecall_encl1_update_operation_t;

typedef struct ms_ocall_encl1_sample_t {
	char* ms_str;
} ms_ocall_encl1_sample_t;

static sgx_status_t SGX_CDECL sgx_ecall_encl1_AES_GCM_decrypt(void* pms)
{
	ms_ecall_encl1_AES_GCM_decrypt_t* ms = SGX_CAST(ms_ecall_encl1_AES_GCM_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_p_src = ms->ms_p_src;
	size_t _len_p_src = _tmp_p_src ? strlen(_tmp_p_src) + 1 : 0;
	char* _in_p_src = NULL;
	char* _tmp_p_dec = ms->ms_p_dec;
	size_t _len_p_dec = 100 * sizeof(*_tmp_p_dec);
	char* _in_p_dec = NULL;
	uint32_t* _tmp_dec_len = ms->ms_dec_len;
	size_t _len_dec_len = sizeof(*_tmp_dec_len);
	uint32_t* _in_dec_len = NULL;

	if (100 > (SIZE_MAX / sizeof(*_tmp_p_dec))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encl1_AES_GCM_decrypt_t));
	CHECK_UNIQUE_POINTER(_tmp_p_src, _len_p_src);
	CHECK_UNIQUE_POINTER(_tmp_p_dec, _len_p_dec);
	CHECK_UNIQUE_POINTER(_tmp_dec_len, _len_dec_len);

	if (_tmp_p_src != NULL) {
		_in_p_src = (char*)malloc(_len_p_src);
		if (_in_p_src == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_src, _tmp_p_src, _len_p_src);
		_in_p_src[_len_p_src - 1] = '\0';
	}
	if (_tmp_p_dec != NULL) {
		if ((_in_p_dec = (char*)malloc(_len_p_dec)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_dec, 0, _len_p_dec);
	}
	if (_tmp_dec_len != NULL) {
		if ((_in_dec_len = (uint32_t*)malloc(_len_dec_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dec_len, 0, _len_dec_len);
	}
	ecall_encl1_AES_GCM_decrypt((const char*)_in_p_src, ms->ms_src_len, _in_p_dec, _in_dec_len);
err:
	if (_in_p_src) free((void*)_in_p_src);
	if (_in_p_dec) {
		memcpy(_tmp_p_dec, _in_p_dec, _len_p_dec);
		free(_in_p_dec);
	}
	if (_in_dec_len) {
		memcpy(_tmp_dec_len, _in_dec_len, _len_dec_len);
		free(_in_dec_len);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_encl1_update_operation(void* pms)
{
	ms_ecall_encl1_update_operation_t* ms = SGX_CAST(ms_ecall_encl1_update_operation_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_key = ms->ms_key;
	size_t _len_key = _tmp_key ? strlen(_tmp_key) + 1 : 0;
	char* _in_key = NULL;
	int* _tmp_flag = ms->ms_flag;
	size_t _len_flag = sizeof(*_tmp_flag);
	int* _in_flag = NULL;
	int* _tmp_vlen = ms->ms_vlen;
	size_t _len_vlen = sizeof(*_tmp_vlen);
	int* _in_vlen = NULL;
	char* _tmp_value = ms->ms_value;
	size_t _len_value = _tmp_value ? strlen(_tmp_value) + 1 : 0;
	char* _in_value = NULL;
	char* _tmp_value_update = ms->ms_value_update;
	size_t _len_value_update = _tmp_value_update ? strlen(_tmp_value_update) + 1 : 0;
	char* _in_value_update = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encl1_update_operation_t));
	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);
	CHECK_UNIQUE_POINTER(_tmp_flag, _len_flag);
	CHECK_UNIQUE_POINTER(_tmp_vlen, _len_vlen);
	CHECK_UNIQUE_POINTER(_tmp_value, _len_value);
	CHECK_UNIQUE_POINTER(_tmp_value_update, _len_value_update);

	if (_tmp_key != NULL) {
		_in_key = (char*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key, _tmp_key, _len_key);
		_in_key[_len_key - 1] = '\0';
	}
	if (_tmp_flag != NULL) {
		_in_flag = (int*)malloc(_len_flag);
		if (_in_flag == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_flag, _tmp_flag, _len_flag);
	}
	if (_tmp_vlen != NULL) {
		_in_vlen = (int*)malloc(_len_vlen);
		if (_in_vlen == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_vlen, _tmp_vlen, _len_vlen);
	}
	if (_tmp_value != NULL) {
		_in_value = (char*)malloc(_len_value);
		if (_in_value == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_value, _tmp_value, _len_value);
		_in_value[_len_value - 1] = '\0';
	}
	if (_tmp_value_update != NULL) {
		_in_value_update = (char*)malloc(_len_value_update);
		if (_in_value_update == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_value_update, _tmp_value_update, _len_value_update);
		_in_value_update[_len_value_update - 1] = '\0';
	}
	ecall_encl1_update_operation(_in_key, _in_flag, _in_vlen, _in_value, _in_value_update);
err:
	if (_in_key) free(_in_key);
	if (_in_flag) free(_in_flag);
	if (_in_vlen) free(_in_vlen);
	if (_in_value) {
		memcpy(_tmp_value, _in_value, _len_value);
		free(_in_value);
	}
	if (_in_value_update) free(_in_value_update);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_ecall_encl1_AES_GCM_decrypt, 0},
		{(void*)(uintptr_t)sgx_ecall_encl1_update_operation, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][2];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_encl1_sample(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_encl1_sample_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_encl1_sample_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_encl1_sample_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_encl1_sample_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

