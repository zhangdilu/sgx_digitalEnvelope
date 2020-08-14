/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include <enclave_t.h>
#include "enclave.h"

#include <sgx_tcrypto.h>
#include <sgx_utils.h>
#include <sgx_tseal.h>

/**
 * This function generates a key pair and then seals the private key.
 *
 * @param pubkey                 Output parameter for public key.
 * @param pubkey_size            Input parameter for size of public key.
 * @param sealedprivkey          Output parameter for sealed private key.
 * @param sealedprivkey_size     Input parameter for size of sealed private key.
 *
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success, some
 *                               sgx_status_t value upon failure.
 */
sgx_status_t ecall_key_gen_and_seal(char *pubkey, size_t pubkey_size, char *sealedprivkey, size_t sealedprivkey_size)
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  size_t byte_size = 256;
  size_t p_byte_size = byte_size/2;
  size_t e_byte_size = 4;
  unsigned char e[4] = {1, 0, 1};
  unsigned char *n =(unsigned char *)malloc(byte_size);
  unsigned char *d = (unsigned char *)malloc(byte_size);
  unsigned char *p = (unsigned char *)malloc(p_byte_size);
  unsigned char *q = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_dmp1 = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_dmq1 = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_iqmp = (unsigned char *)malloc(p_byte_size);
  uint8_t *p_private = (uint8_t *)malloc(5*p_byte_size);
  
  if ((ret = sgx_create_rsa_key_pair(byte_size, e_byte_size, n, d, e, p, q, p_dmp1, p_dmq1, p_iqmp)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_create_rsa_key_pair() failed !\n");
    goto cleanup;
  }
  memcpy(p_private,p,p_byte_size);
  memcpy(p_private+p_byte_size,q,p_byte_size);
  memcpy(p_private+p_byte_size*2,p_dmp1,p_byte_size);
  memcpy(p_private+p_byte_size*3,p_dmq1,p_byte_size);
  memcpy(p_private+p_byte_size*4,p_iqmp,p_byte_size);
  memcpy(pubkey,n,byte_size);
  
  //print("n:");printh(n,byte_size);
  //print("\nseal:");printh(p_private,p_byte_size*5);
  if (sealedprivkey_size >= sgx_calc_sealed_data_size(0U, p_byte_size*5))
  {
    if ((ret = sgx_seal_data(0U, NULL, p_byte_size*5, (uint8_t *)p_private, (uint32_t)sealedprivkey_size, (sgx_sealed_data_t *)sealedprivkey)) != SGX_SUCCESS)
    {

      print("\nTrustedApp: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  }
  else
  {
    print("\nTrustedApp: Size allocated for sealedprivkey by untrusted app is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
	      
  print("\nTrustedApp: Key pair generated and private key was sealed. Sent the public key and sealed private key back.\n");
  ret = SGX_SUCCESS;

cleanup:
free(n);free(d); free(p); free(q); free(p_dmp1); free(p_dmq1); free(p_iqmp);free(p_private);
return ret;
}
/*{
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  // Step 2: Create Key Pair.
  sgx_ec256_private_t p_private;
  if ((ret = sgx_ecc256_create_key_pair(&p_private, (sgx_ec256_public_t *)pubkey, p_ecc_handle)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_ecc256_create_key_pair() failed !\n");
    goto cleanup;
 }

  if (sealedprivkey_size >= sgx_calc_sealed_data_size(0U, sizeof(p_private)))
  {
    if ((ret = sgx_seal_data(0U, NULL, sizeof(p_private), (uint8_t *)&p_private, (uint32_t) sealedprivkey_size, (sgx_sealed_data_t *)sealedprivkey)) != SGX_SUCCESS)
    {
      print("\nTrustedApp: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  }
  else
  {
    print("\nTrustedApp: Size allocated for sealedprivkey by untrusted app is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  print("\nTrustedApp: Key pair generated and private key was sealed. Sent the public key and sealed private key back.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (p_ecc_handle != NULL)
  {
    sgx_ecc256_close_context(p_ecc_handle);
  }

return ret;
}*/
