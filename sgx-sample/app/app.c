/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <getopt.h>

#include <openssl/evp.h>

#include "app.h"


static struct option long_options[] = {
    {"keygen", no_argument, 0, 0},
    {"decrypt", no_argument, 0, 0},
    {"enclave-path", required_argument, 0, 0},
    {"statefile", required_argument, 0, 0},
    {"encrypted-aes-key", required_argument, 0, 0},
    {"public-key", required_argument, 0, 0},
    {0, 0, 0, 0}};


/**
 * main()
 */
int main(int argc,char **argv){
	test(argc,argv);
}
int test(int argc, char **argv)
{
    bool opt_keygen = false;
    bool opt_decrypt = false;
    const char *opt_enclave_path = NULL;
    const char *opt_statefile = NULL;
    const char *opt_aes_key_file = NULL;
    const char *opt_input_file = NULL;
    const char *opt_public_key_file = NULL;

    int option_index = 0;

    while (getopt_long_only(argc, argv, "", long_options, &option_index) != -1)
    {
        switch (option_index)
        {
        case 0:
            opt_keygen = true;
            break;
        case 1:
            opt_decrypt = true;
            break;
        case 2:
            opt_enclave_path = optarg;
            break;
        case 3:
            opt_statefile = optarg;
            break;
        case 4:
            opt_aes_key_file = optarg;
            break;
        case 5:
            opt_public_key_file = optarg;
            break;
        }
    }

    if (optind < argc)
    {
        opt_input_file = argv[optind++];
    }

    if (!opt_keygen && !opt_decrypt)
    {
        fprintf(stderr, "Error: Must specifiy --keygen, --encrypt or --decrypt\n");
        return EXIT_FAILURE;
    }

    if (opt_keygen && (!opt_enclave_path || !opt_statefile || !opt_public_key_file))
    {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s --keygen --enclave-path /path/to/enclave.signed.so --statefile sealeddata.bin --public-key mykey.pem\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (opt_decrypt && (!opt_enclave_path || !opt_statefile || !opt_input_file))
    {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s --decrypt --enclave-path /path/to/enclave.signed.so --statefile sealeddata.bin --encrypted-aes-key keyfile inputfile\n", argv[0]);
        return EXIT_FAILURE;
    }

    OpenSSL_add_all_algorithms(); /* Init OpenSSL lib */

    bool success_status = create_enclave(opt_enclave_path) &&
                          enclave_get_buffer_sizes() &&
                          allocate_buffers() &&
                          (opt_decrypt? load_enclave_state(opt_statefile) : true) &&
                          (opt_keygen ? enclave_generate_key() : true) &&
                          (opt_decrypt ? load_ase_file(opt_aes_key_file) : true) &&
                          (opt_decrypt ? load_input_file(opt_input_file) : true) &&
                          (opt_decrypt ? enclave_decrypt_data() : true) &&
                          save_enclave_state(opt_statefile) &&
                          (opt_keygen ? save_public_key(opt_public_key_file) : true);

    if (sgx_lasterr != SGX_SUCCESS)
    {
        fprintf(stderr, "[GatewayApp]: ERROR: %s\n", decode_sgx_status(sgx_lasterr));
    }

    destroy_enclave();
    cleanup_buffers();

    return success_status ? EXIT_SUCCESS : EXIT_FAILURE;
}
