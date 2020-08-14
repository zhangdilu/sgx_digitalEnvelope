#include <stdio.h>
#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include "app.h"

bool load_input_file(const char *const input_file)
{
    printf("[GatewayApp]: Loading input file\n");

    return read_file_into_memory(input_file, &input_buffer, &input_buffer_size);
}

bool load_ase_file(const char *const aes_key_file)
{
    printf("[GatewayApp]: Loading input file\n");

    return read_file_into_memory(aes_key_file, &encrypted_aes_buffer, &encrypted_aes_buffer_size);
}

bool enclave_decrypt_data()
{
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

    printf("[GatewayApp]: Calling enclave to generate key material\n");
    sgx_lasterr = ecall_unseal_and_decrypt(enclave_id,
                                        &ecall_retval,
                                        (uint8_t *)input_buffer,
                                        (uint32_t)input_buffer_size,
                                        (uint8_t *)encrypted_aes_buffer,
                                        (uint32_t)encrypted_aes_buffer_size,
                                        (char *)sealed_data_buffer,
                                        sealed_data_buffer_size);
    if (sgx_lasterr == SGX_SUCCESS &&
        (ecall_retval != 0))
    {
        fprintf(stderr, "[GatewayApp]: ERROR: ecall_unseal_and_decrypt returned %d\n", ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    return (sgx_lasterr == SGX_SUCCESS);
}
