#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_PRINT_HEX_DEFINED__
#define OCALL_PRINT_HEX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_hex, (unsigned char* str, size_t size));
#endif

sgx_status_t ecall_key_gen_and_seal(sgx_enclave_id_t eid, sgx_status_t* retval, char* pubkey, size_t pubkey_size, char* sealedprivkey, size_t sealedprivkey_size);
sgx_status_t ecall_calc_buffer_sizes(sgx_enclave_id_t eid, sgx_status_t* retval, size_t* epubkey_size, size_t* esealedprivkey_size);
sgx_status_t ecall_unseal_and_decrypt(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* msg, uint32_t msg_size, uint8_t* encrypted_key, uint32_t encrypted_key_size, char* sealed, size_t sealed_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
