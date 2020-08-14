#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_key_gen_and_seal_t {
	sgx_status_t ms_retval;
	char* ms_pubkey;
	size_t ms_pubkey_size;
	char* ms_sealedprivkey;
	size_t ms_sealedprivkey_size;
} ms_ecall_key_gen_and_seal_t;

typedef struct ms_ecall_calc_buffer_sizes_t {
	sgx_status_t ms_retval;
	size_t* ms_epubkey_size;
	size_t* ms_esealedprivkey_size;
} ms_ecall_calc_buffer_sizes_t;

typedef struct ms_ecall_unseal_and_decrypt_t {
	sgx_status_t ms_retval;
	uint8_t* ms_msg;
	uint32_t ms_msg_size;
	uint8_t* ms_encrypted_key;
	uint32_t ms_encrypted_key_size;
	char* ms_sealed;
	size_t ms_sealed_size;
} ms_ecall_unseal_and_decrypt_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_print_hex_t {
	unsigned char* ms_str;
	size_t ms_size;
} ms_ocall_print_hex_t;

static sgx_status_t SGX_CDECL sgx_ecall_key_gen_and_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_key_gen_and_seal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_key_gen_and_seal_t* ms = SGX_CAST(ms_ecall_key_gen_and_seal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_pubkey = ms->ms_pubkey;
	size_t _tmp_pubkey_size = ms->ms_pubkey_size;
	size_t _len_pubkey = _tmp_pubkey_size;
	char* _in_pubkey = NULL;
	char* _tmp_sealedprivkey = ms->ms_sealedprivkey;
	size_t _tmp_sealedprivkey_size = ms->ms_sealedprivkey_size;
	size_t _len_sealedprivkey = _tmp_sealedprivkey_size;
	char* _in_sealedprivkey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_pubkey, _len_pubkey);
	CHECK_UNIQUE_POINTER(_tmp_sealedprivkey, _len_sealedprivkey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pubkey != NULL && _len_pubkey != 0) {
		if ( _len_pubkey % sizeof(*_tmp_pubkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pubkey = (char*)malloc(_len_pubkey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pubkey, 0, _len_pubkey);
	}
	if (_tmp_sealedprivkey != NULL && _len_sealedprivkey != 0) {
		if ( _len_sealedprivkey % sizeof(*_tmp_sealedprivkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealedprivkey = (char*)malloc(_len_sealedprivkey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedprivkey, 0, _len_sealedprivkey);
	}

	ms->ms_retval = ecall_key_gen_and_seal(_in_pubkey, _tmp_pubkey_size, _in_sealedprivkey, _tmp_sealedprivkey_size);
	if (_in_pubkey) {
		if (memcpy_s(_tmp_pubkey, _len_pubkey, _in_pubkey, _len_pubkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sealedprivkey) {
		if (memcpy_s(_tmp_sealedprivkey, _len_sealedprivkey, _in_sealedprivkey, _len_sealedprivkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_pubkey) free(_in_pubkey);
	if (_in_sealedprivkey) free(_in_sealedprivkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_calc_buffer_sizes(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_calc_buffer_sizes_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_calc_buffer_sizes_t* ms = SGX_CAST(ms_ecall_calc_buffer_sizes_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	size_t* _tmp_epubkey_size = ms->ms_epubkey_size;
	size_t _len_epubkey_size = sizeof(size_t);
	size_t* _in_epubkey_size = NULL;
	size_t* _tmp_esealedprivkey_size = ms->ms_esealedprivkey_size;
	size_t _len_esealedprivkey_size = sizeof(size_t);
	size_t* _in_esealedprivkey_size = NULL;

	CHECK_UNIQUE_POINTER(_tmp_epubkey_size, _len_epubkey_size);
	CHECK_UNIQUE_POINTER(_tmp_esealedprivkey_size, _len_esealedprivkey_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_epubkey_size != NULL && _len_epubkey_size != 0) {
		if ( _len_epubkey_size % sizeof(*_tmp_epubkey_size) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_epubkey_size = (size_t*)malloc(_len_epubkey_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_epubkey_size, 0, _len_epubkey_size);
	}
	if (_tmp_esealedprivkey_size != NULL && _len_esealedprivkey_size != 0) {
		if ( _len_esealedprivkey_size % sizeof(*_tmp_esealedprivkey_size) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_esealedprivkey_size = (size_t*)malloc(_len_esealedprivkey_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_esealedprivkey_size, 0, _len_esealedprivkey_size);
	}

	ms->ms_retval = ecall_calc_buffer_sizes(_in_epubkey_size, _in_esealedprivkey_size);
	if (_in_epubkey_size) {
		if (memcpy_s(_tmp_epubkey_size, _len_epubkey_size, _in_epubkey_size, _len_epubkey_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_esealedprivkey_size) {
		if (memcpy_s(_tmp_esealedprivkey_size, _len_esealedprivkey_size, _in_esealedprivkey_size, _len_esealedprivkey_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_epubkey_size) free(_in_epubkey_size);
	if (_in_esealedprivkey_size) free(_in_esealedprivkey_size);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_unseal_and_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_unseal_and_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_unseal_and_decrypt_t* ms = SGX_CAST(ms_ecall_unseal_and_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_msg = ms->ms_msg;
	uint32_t _tmp_msg_size = ms->ms_msg_size;
	size_t _len_msg = _tmp_msg_size;
	uint8_t* _in_msg = NULL;
	uint8_t* _tmp_encrypted_key = ms->ms_encrypted_key;
	uint32_t _tmp_encrypted_key_size = ms->ms_encrypted_key_size;
	size_t _len_encrypted_key = _tmp_encrypted_key_size;
	uint8_t* _in_encrypted_key = NULL;
	char* _tmp_sealed = ms->ms_sealed;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed = _tmp_sealed_size;
	char* _in_sealed = NULL;

	CHECK_UNIQUE_POINTER(_tmp_msg, _len_msg);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_key, _len_encrypted_key);
	CHECK_UNIQUE_POINTER(_tmp_sealed, _len_sealed);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_msg != NULL && _len_msg != 0) {
		if ( _len_msg % sizeof(*_tmp_msg) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_msg = (uint8_t*)malloc(_len_msg);
		if (_in_msg == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_msg, _len_msg, _tmp_msg, _len_msg)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encrypted_key != NULL && _len_encrypted_key != 0) {
		if ( _len_encrypted_key % sizeof(*_tmp_encrypted_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted_key = (uint8_t*)malloc(_len_encrypted_key);
		if (_in_encrypted_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted_key, _len_encrypted_key, _tmp_encrypted_key, _len_encrypted_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed != NULL && _len_sealed != 0) {
		if ( _len_sealed % sizeof(*_tmp_sealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed = (char*)malloc(_len_sealed);
		if (_in_sealed == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed, _len_sealed, _tmp_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_unseal_and_decrypt(_in_msg, _tmp_msg_size, _in_encrypted_key, _tmp_encrypted_key_size, _in_sealed, _tmp_sealed_size);

err:
	if (_in_msg) free(_in_msg);
	if (_in_encrypted_key) free(_in_encrypted_key);
	if (_in_sealed) free(_in_sealed);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_ecall_key_gen_and_seal, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_calc_buffer_sizes, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_unseal_and_decrypt, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][3];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_hex(unsigned char* str, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = size;

	ms_ocall_print_hex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_hex_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_hex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_hex_t));
	ocalloc_size -= sizeof(ms_ocall_print_hex_t);

	if (str != NULL) {
		ms->ms_str = (unsigned char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

