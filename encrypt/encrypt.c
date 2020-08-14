#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include "encrypt.h"


static struct option long_options[] = {
    {"keygen", no_argument, 0, 0},
    {"aes-key", required_argument, 0, 0},
    {"public-key", required_argument, 0, 0},
    {"encrypted-aes-key", required_argument, 0, 0},
    {"ciphertext", required_argument, 0, 0},
    {0, 0, 0, 0}};

static void ctr128_inc(unsigned char *counter)
{
	unsigned int n = 16, c = 1;

	do {
		--n;
		c += counter[n];
		counter[n] = (unsigned char)c;
		c >>= 8;
	} while (n);
}
int main(int argc, char **argv)
{
    bool opt_keygen = false;
    const char *opt_aes_key_file = NULL;
    const char *opt_input_file = NULL;
    const char *opt_public_key_file = NULL;
    const char *opt_encrypted_key_file = NULL;
    const char *opt_ciphertext_file = NULL;

    int option_index = 0;

    while (getopt_long_only(argc, argv, "", long_options, &option_index) != -1)
    {
        switch (option_index)
        {
        case 0:
            opt_keygen = true;
            break;
        case 1:
            opt_aes_key_file = optarg;
            break;
        case 2:
            opt_public_key_file = optarg;
            break;
        case 3:
            opt_encrypted_key_file = optarg;
            break;
        case 4:
            opt_ciphertext_file = optarg;
            break;

        }
    }

    if (optind < argc)
    {
        opt_input_file = argv[optind++];
    }

    if (!opt_input_file || !opt_public_key_file || !opt_encrypted_key_file || !opt_ciphertext_file)
    {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s [--keygen] --public-key mykey.pem --aes-key aes.bin --encrypted-aes-key e_aes.bin --ciphertext cipherfile inputfile\n",argv[0]);
        return EXIT_FAILURE;
    }

    OpenSSL_add_all_algorithms(); /* Init OpenSSL lib */

    EVP_PKEY* rsa=open_public_key(opt_public_key_file);
    encrypted_aes_buffer_size=256;
	encrypted_aes_buffer=(unsigned char* )malloc(encrypted_aes_buffer_size);

    bool success_status = (opt_keygen ? generate_aes_key():read_file_into_memory(opt_aes_key_file,&aes_buffer,&aes_buffer_size)) &&
                          read_file_into_memory(opt_input_file,&input_buffer,&input_buffer_size) &&
                          rsa_encrypt_data(rsa, encrypted_aes_buffer, &encrypted_aes_buffer_size, aes_buffer, aes_buffer_size) &&
                          (opt_keygen ? save_aes_key(opt_aes_key_file) : true) &&
                          save_encrypt_aes_key(opt_encrypted_key_file) &&
                          aes_encrypt_data() &&
                          save_ciphertext(opt_ciphertext_file);

    if(input_buffer)free(input_buffer);
    if(aes_buffer)free(aes_buffer);
    if(encrypted_aes_buffer)free(encrypted_aes_buffer);
    if(public_key_buffer)free(public_key_buffer);
    if(encrypt_buffer)free(encrypt_buffer);
    return success_status ? EXIT_SUCCESS : EXIT_FAILURE;
}

EVP_PKEY* open_public_key(const char *keyfile)
{
	EVP_PKEY* key = NULL;
	RSA *rsa = NULL;

	BIO *bp = BIO_new(BIO_s_file());;
	BIO_read_filename(bp, keyfile);
	if(NULL == bp)
	{
		printf("open_public_key bio file new error!\n");
		return NULL;
	}

	rsa = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
	if(rsa == NULL)
	{
		printf("open_public_key failed to PEM_read_bio_RSAPublicKey!\n");
		BIO_free(bp);
		RSA_free(rsa);

		return NULL;
	}

	printf("open_public_key success to PEM_read_bio_RSAPublicKey!\n");
	key = EVP_PKEY_new();
	if(NULL == key)
	{
		printf("open_public_key EVP_PKEY_new failed\n");
		RSA_free(rsa);

		return NULL;
	}

	EVP_PKEY_assign_RSA(key, rsa);
	return key;
}
bool rsa_encrypt_data(void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len)
{
    if (rsa_key == NULL || pout_len == NULL || pin_data == NULL || pin_len < 1 || pin_len >= INT_MAX)
    {
        return false;
    }

    bool ret_code = false;
    EVP_PKEY_CTX *ctx = NULL;

    do {
        ctx = EVP_PKEY_CTX_new((EVP_PKEY*)rsa_key, NULL);
        if ((ctx == NULL) || (EVP_PKEY_encrypt_init(ctx) < 1))
        {
                break;
        }

        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

        if (EVP_PKEY_encrypt(ctx, pout_data, pout_len, pin_data, pin_len) <= 0)
        {
                break;
        }

        ret_code = true;
    } while (0);

    EVP_PKEY_CTX_free(ctx);
    return ret_code;
}
bool generate_aes_key()
{
    bool ret_status = true;
    aes_buffer_size=16;
    aes_buffer=(unsigned char* )malloc(aes_buffer_size);
    ctr_buffer_size=16;
    ctr_buffer=(unsigned char* )malloc(ctr_buffer_size);
    if (!RAND_bytes(aes_buffer, aes_buffer_size)) {
        fprintf(stderr, "generate_aes_key() failed\n");
        ret_status = false;
    }
    if (!RAND_bytes(ctr_buffer, ctr_buffer_size)) {
        fprintf(stderr, "generate_aes_key() failed\n");
        ret_status = false;
    }

    return ret_status;
}
bool aes_encrypt_data()
{
    encrypt_buffer_size=input_buffer_size;
    encrypt_buffer=(unsigned char *)malloc(encrypt_buffer_size);
    if ((input_buffer_size > INT_MAX) || (aes_buffer == NULL) || (input_buffer == NULL) || (ctr_buffer == NULL) || (encrypt_buffer == NULL))
	{
		return false;
	}

	bool ret_status = true;
	int len = 0;
	EVP_CIPHER_CTX* ptr_ctx = NULL;
	unsigned char *p_ctr=(unsigned char* )malloc(ctr_buffer_size);
	memcpy(p_ctr,ctr_buffer,ctr_buffer_size);

	do {
		// Create and init ctx
		//
		if (!(ptr_ctx = EVP_CIPHER_CTX_new())) {
			ret_status = false;
			break;
		}
		// Initialise encrypt, key
		//
		if (1 != EVP_EncryptInit_ex(ptr_ctx, EVP_aes_128_ctr(), NULL, aes_buffer, p_ctr)) {
			break;
		}

		// Provide the message to be encrypted, and obtain the encrypted output.
		//
		if (1 != EVP_EncryptUpdate(ptr_ctx, encrypt_buffer, &len, input_buffer, input_buffer_size)) {
			break;
		}
		// Finalise the encryption
		//
		if (1 != EVP_EncryptFinal_ex(ptr_ctx, encrypt_buffer + len, &len)) {
			break;
		}
		// Encryption success, increment counter
		//
		len = input_buffer_size;
		while (len >= 0) {
			ctr128_inc(p_ctr);
			len -= 16;
		}
		ret_status = true;
	} while (0);
	//clean up ctx and return
	//
	if (ptr_ctx) {
		EVP_CIPHER_CTX_free(ptr_ctx);
	}
	free(p_ctr);
	return ret_status;
}
bool read_file_into_memory(const char *const filename, void **buffer, size_t *buffer_size)
{
    bool ret_status = true;
    FILE *file = NULL;
    long file_len = 0L;

    if (buffer == NULL || buffer_size == NULL)
    {
        fprintf(stderr, "read_file_into_memory() invalid parameter\n");
        ret_status = false;
        goto cleanup;
    }

    file = fopen(filename, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "read_file_into_memory() fopen failed\n");
        ret_status = false;
        goto cleanup;
    }

    fseek(file, 0, SEEK_END);
    file_len = ftell(file);
    if (file_len < 0 || file_len > INT_MAX)
    {
        fprintf(stderr, "Invalid input file size\n");
        ret_status = false;
        goto cleanup;
    }

    *buffer_size = (size_t)file_len;
    *buffer = malloc(*buffer_size);
    if (*buffer == NULL)
    {
        fprintf(stderr, "read_file_into_memory() memory allocation failed\n");
        ret_status = false;
        goto cleanup;
    }

    fseek(file, 0, SEEK_SET);
    if (fread(*buffer, *buffer_size, 1, file) != 1)
    {
        fprintf(stderr, "Input file only partially read.\n");
        ret_status = false;
        goto cleanup;
    }

cleanup:
    if (file != NULL)
    {
        fclose(file);
    }

    return ret_status;
}

bool save_ciphertext(const char *const ciphertext_file)
{
    bool ret_status = true;
    FILE *file = fopen(ciphertext_file, "wb");
    if (file == NULL)
    {
        fprintf(stderr, "save_ciphertext() fopen failed\n");
        ret_status = false;
        goto cleanup;
    }

    if (fwrite(ctr_buffer, ctr_buffer_size, 1, file) != 1)
    {
        fprintf(stderr, "ERROR: Could not write ciphertext\n");
        ret_status = false;
        goto cleanup;
    }

    if (fwrite(encrypt_buffer, encrypt_buffer_size, 1, file) != 1)
    {
        fprintf(stderr, "ERROR: Could not write ciphertext\n");
        ret_status = false;
        goto cleanup;
    }

cleanup:
    if (file != NULL)
    {
        fclose(file);
    }

    return ret_status;
}
bool save_aes_key(const char *const aes_file)
{
    bool ret_status = true;
    FILE *file = fopen(aes_file, "wb");
    if (file == NULL)
    {
        fprintf(stderr, "save_aes_key() fopen failed\n");
        ret_status = false;
        goto cleanup;
    }

    if (fwrite(aes_buffer, aes_buffer_size, 1, file) != 1)
    {
        fprintf(stderr, "ERROR: Could not write aeskey\n");
        ret_status = false;
        goto cleanup;
    }

cleanup:
    if (file != NULL)
    {
        fclose(file);
    }

    return ret_status;
}
bool save_encrypt_aes_key(const char *const encrypted_aes_file)
{
    bool ret_status = true;
    FILE *file = fopen(encrypted_aes_file, "wb");
    if (file == NULL)
    {
        fprintf(stderr, "save_encrypt_aes_key() fopen failed\n");
        ret_status = false;
        goto cleanup;
    }

    if (fwrite(encrypted_aes_buffer, encrypted_aes_buffer_size, 1, file) != 1)
    {
        fprintf(stderr, "ERROR: Could not write encrypt_aes_key\n");
        ret_status = false;
        goto cleanup;
    }

cleanup:
    if (file != NULL)
    {
        fclose(file);
    }

    return ret_status;
}
