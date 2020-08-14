#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <enclave_t.h>
#include "enclave.h"

#include <sgx_tcrypto.h>
#include <sgx_utils.h>
#include <sgx_tseal.h>

sgx_status_t ecall_unseal_and_decrypt(uint8_t *msg, uint32_t msg_size, uint8_t *encrypted_key, uint32_t encrypted_key_size, char *sealed, size_t sealed_size)
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  void *new_pri_key2=NULL;
  int byte_size = 256;
  size_t p_byte_size = byte_size/2;
  int e_byte_size = 4;
  unsigned char e[4] = {1, 0, 1};
  unsigned char *p = (unsigned char *)malloc(p_byte_size);
  unsigned char *q = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_dmp1 = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_dmq1 = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_iqmp = (unsigned char *)malloc(p_byte_size);
  size_t aeskey_size=0;
  unsigned char *aeskey=NULL;
  size_t ctr_size=16;
  uint8_t *p_ctr=(uint8_t *)malloc(ctr_size);
  uint32_t text_size=msg_size-ctr_size;
  uint8_t *p_src=(uint8_t *)malloc(text_size);
  uint8_t *p_dst=(uint8_t *)malloc(text_size);


  print("\nTrustedApp: Received sensor data and the sealed private key.\n");
  uint32_t unsealed_data_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed);

  uint8_t *unsealed_data = (uint8_t *)malloc(unsealed_data_size);
  if (unsealed_data == NULL)
  {
    print("\nTrustedApp: malloc(unsealed_data_size) failed !\n");
    goto cleanup;
  }

  if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, NULL, unsealed_data, &unsealed_data_size)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_unseal_data() failed !\n");
    goto cleanup;
  }

  memcpy(p,unsealed_data,p_byte_size);
  memcpy(q,unsealed_data+p_byte_size,p_byte_size);
  memcpy(p_dmp1,unsealed_data+p_byte_size*2,p_byte_size);
  memcpy(p_dmq1,unsealed_data+p_byte_size*3,p_byte_size);
  memcpy(p_iqmp,unsealed_data+p_byte_size*4,p_byte_size);
  if ((ret = sgx_create_rsa_priv2_key(byte_size, e_byte_size, e, p, q, p_dmp1, p_dmq1, p_iqmp, &new_pri_key2)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_create_rsa_priv2_key() failed !\n");
    goto cleanup;
  }

  if ((ret = sgx_rsa_priv_decrypt_sha256(new_pri_key2, NULL, &aeskey_size,encrypted_key,encrypted_key_size)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_rsa_priv_decrypt_sha256() failed !\n");
    goto cleanup;
  }
  aeskey=(unsigned char *)malloc(aeskey_size);
  if ((ret = sgx_rsa_priv_decrypt_sha256(new_pri_key2, aeskey, &aeskey_size,encrypted_key,encrypted_key_size)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_rsa_priv_decrypt_sha256() failed !\n");
    goto cleanup;
  }

  /*print("p:");printh(p,p_byte_size);print("\n");
  print("p:");printh(p,p_byte_size);print("\n");
  print("q:");printh(q,p_byte_size);print("\n");
  print("e:");printh(e,4);print("\n");
  print("p_dmp1:");printh(p_dmp1,p_byte_size);print("\n");
  print("p_dmq1:");printh(p_dmq1,p_byte_size);print("\n");
  print("p_iqmp:");printh(p_iqmp,p_byte_size);print("\n");
  print("aeskey:");printh(aeskey,aeskey_size);print("\n");*/
  print("aes_key:");print(aeskey);
  memcpy(p_ctr,msg,ctr_size);
  memcpy(p_src,msg+ctr_size,text_size);
  sgx_aes_ctr_decrypt(aeskey,p_src,text_size,p_ctr,128,p_dst);
  print(p_dst);
  print("\nTrustedApp: Unsealed the sealed private key, decrypted sensor data with this private key.\n");
  ret = SGX_SUCCESS;

cleanup:
  if (unsealed_data != NULL)
  {
    memset_s(unsealed_data, unsealed_data_size, 0, unsealed_data_size);
    free(unsealed_data);
  }
  if (aeskey != NULL)
  {
    memset_s(aeskey, aeskey_size, 0, aeskey_size);
    free(aeskey);
  }
  memset_s(p_src, text_size, 0, text_size);free(p_src);
  memset_s(p_ctr, ctr_size, 0, ctr_size);free(p_ctr);
  memset_s(p_dst, text_size, 0, text_size);free(p_dst);
  memset_s(p, p_byte_size, 0, p_byte_size);free(p);
  memset_s(q, p_byte_size, 0, p_byte_size);free(q);
  memset_s(p_dmp1, p_byte_size, 0, p_byte_size);free(p_dmp1);
  memset_s(p_dmq1, p_byte_size, 0, p_byte_size);free(p_dmq1);
  memset_s(p_iqmp, p_byte_size, 0, p_byte_size);free(p_iqmp);
  if(new_pri_key2)sgx_free_rsa_key(new_pri_key2,SGX_RSA_PRIVATE_KEY,byte_size,e_byte_size);

return ret;
}
