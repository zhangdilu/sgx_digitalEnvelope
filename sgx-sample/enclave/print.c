/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <enclave_t.h>
#include "enclave.h"

void print(const char * const str)
{
  ocall_print_string(str);
}
void printh(unsigned char* p,size_t size)
{
	    ocall_print_hex(p,size);
}
