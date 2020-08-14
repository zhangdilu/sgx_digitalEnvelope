/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

/* Ensure that ocall_print_string has exern C linkage */
#include <enclave_u.h>

void ocall_print_string(const char *str)
{
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
}
void ocall_print_hex(unsigned char *p,size_t size)
{
	    int i=0;
	    for(i=0;i<size;i++){
            printf("%02x",p[i]);
        };
}
