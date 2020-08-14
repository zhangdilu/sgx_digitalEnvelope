#include "enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_print_hex(void* pms)
{
	ms_ocall_print_hex_t* ms = SGX_CAST(ms_ocall_print_hex_t*, pms);
	ocall_print_hex(ms->ms_str, ms->ms_size);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_enclave = {
	2,
	{
		(void*)enclave_ocall_print_string,
		(void*)enclave_ocall_print_hex,
	}
};
sgx_status_t ecall_key_gen_and_seal(sgx_enclave_id_t eid, sgx_status_t* retval, char* pubkey, size_t pubkey_size, char* sealedprivkey, size_t sealedprivkey_size)
{
	sgx_status_t status;
	ms_ecall_key_gen_and_seal_t ms;
	ms.ms_pubkey = pubkey;
	ms.ms_pubkey_size = pubkey_size;
	ms.ms_sealedprivkey = sealedprivkey;
	ms.ms_sealedprivkey_size = sealedprivkey_size;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_calc_buffer_sizes(sgx_enclave_id_t eid, sgx_status_t* retval, size_t* epubkey_size, size_t* esealedprivkey_size)
{
	sgx_status_t status;
	ms_ecall_calc_buffer_sizes_t ms;
	ms.ms_epubkey_size = epubkey_size;
	ms.ms_esealedprivkey_size = esealedprivkey_size;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_unseal_and_decrypt(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* msg, uint32_t msg_size, uint8_t* encrypted_key, uint32_t encrypted_key_size, char* sealed, size_t sealed_size)
{
	sgx_status_t status;
	ms_ecall_unseal_and_decrypt_t ms;
	ms.ms_msg = msg;
	ms.ms_msg_size = msg_size;
	ms.ms_encrypted_key = encrypted_key;
	ms.ms_encrypted_key_size = encrypted_key_size;
	ms.ms_sealed = sealed;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

