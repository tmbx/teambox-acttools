/**
 * Copyright (C) 2010-2012 Opersys inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/* sslsigntool.cpp
 *
 * Copyright (C) 2007-2012 Opersys inc., All rights reserved.
 *
 * July 20th 2007
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <inttypes.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/time.h>
#include <string>
#include <errno.h>
#include <wchar.h>
#include <locale.h>
#include <iconv.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#if defined(LIBGNUTLS_VERSION_MAJOR) && LIBGNUTLS_VERSION_MINOR >= 2
#include <gnutls/compat.h>
#endif

/* Main comment of this file: this is crappy code. It is used to work around
 * crappy code made by other people.
 */

void * malloc_wrapper(int size) {
    void *data = malloc(size);
    
    if (data == NULL) {
	fprintf(stderr, "Out of memory.\n");
	exit(1);
    }
    
    return data;
}

gnutls_datum read_data_file(char *path) {
    int error = 0;
    FILE *data_file = fopen(path, "rb");
    
    if (data_file == NULL) {
	fprintf(stderr, "Cannot open file %s.\n", path);
	exit(1);
    }
    
    gnutls_datum tls_data = { (unsigned char *) malloc_wrapper(10000), 0 };
    
    error = fread(tls_data.data, 1, 10000, data_file);

    if (error <= 0) {
	fprintf(stderr, "Cannot read %s.\n", path);
	exit(1);
    }
    
    tls_data.size = error;
    fclose(data_file);
    
    return tls_data;
}

gnutls_x509_crt read_cert_file(char *path) {
    gnutls_x509_crt cert = NULL;
    gnutls_datum tls_data = read_data_file(path);

    if (gnutls_x509_crt_init(&cert)) {
	fprintf(stderr, "Cannot initialize certificate.\n");
	exit(1);
    }

    if (gnutls_x509_crt_import(cert, &tls_data, GNUTLS_X509_FMT_PEM)) {
	fprintf(stderr, "Cannot import certificate.\n");
	exit(1);
    }
    
    free(tls_data.data);
    return cert;
}

gnutls_x509_crq read_csr_file(char *path) {
    gnutls_x509_crq csr = NULL;
    gnutls_datum tls_data = read_data_file(path);

    if (gnutls_x509_crq_init(&csr)) {
	fprintf(stderr, "Cannot initialize CSR.\n");
	exit(1);
    }

    if (gnutls_x509_crq_import(csr, &tls_data, GNUTLS_X509_FMT_PEM)) {
	fprintf(stderr, "Cannot import CSR.\n");
	exit(1);
    }
    
    free(tls_data.data);
    return csr;
}

gnutls_x509_privkey read_priv_key_file(char *path) {
    gnutls_x509_privkey priv_key = NULL;
    gnutls_datum tls_data = read_data_file(path);

    if (gnutls_x509_privkey_init(&priv_key)) {
	fprintf(stderr, "Cannot initialize private key.\n");
	exit(1);
    }

    if (gnutls_x509_privkey_import(priv_key, &tls_data, GNUTLS_X509_FMT_PEM)) {
	fprintf(stderr, "Cannot import private key.\n");
	exit(1);
    }
    
    free(tls_data.data);
    return priv_key;
}

void sign_file(char *cert_path, char *priv_key_path, char *input_path, char *output_path) {
    gnutls_x509_crt cert = read_cert_file(cert_path);
    gnutls_x509_privkey priv_key = read_priv_key_file(priv_key_path);
    gnutls_datum input = read_data_file(input_path);
    gnutls_datum output = { (unsigned char *) malloc_wrapper(10000), 10000 };
    
    if (gnutls_x509_privkey_sign_data(priv_key, GNUTLS_DIG_SHA, 0, &input, output.data, &output.size)) {
	fprintf(stderr, "Cannot sign data.\n");
	exit(1);
    }
    
    FILE *output_file = fopen(output_path, "wb");
    
    if (! output_file) {
	fprintf(stderr, "Cannot open %s.\n", output_path);
	exit(1);
    }
    
    if (fwrite(output.data, 1, output.size, output_file) != output.size) {
	fprintf(stderr, "Cannot write %s.\n", output_path);
	exit(1);
    }
    
    if (fclose(output_file)) {
	fprintf(stderr, "Cannot close %s.\n", output_path);
	exit(1);
    }
    
    free(input.data);   
    free(output.data);
    gnutls_x509_crt_deinit(cert);
    gnutls_x509_privkey_deinit(priv_key);
}

void verify_file(char *cert_path, char *data_path, char *sig_path) {
    gnutls_x509_crt cert = read_cert_file(cert_path);
    gnutls_datum content = read_data_file(data_path);
    gnutls_datum sig = read_data_file(sig_path);
    
    if (! gnutls_x509_crt_verify_data(cert, 0, &content, &sig)) {
	fprintf(stderr, "Cannot verify signature.\n");
	exit(1);
    }
    
    free(content.data);
    free(sig.data);
    gnutls_x509_crt_deinit(cert);
}

void verify_csr_match_cert(char *csr_path, char *cert_path) {
    gnutls_x509_crq csr = read_csr_file(csr_path);
    gnutls_x509_crt cert_issued = read_cert_file(cert_path);
    gnutls_x509_crt cert_csr;
    gnutls_datum mod1, mod2, exp1, exp2;
    
    if (gnutls_x509_crt_init(&cert_csr)) {
	fprintf(stderr, "Cannot initialize certificate.\n");
	exit(1);
    }
    
    if (gnutls_x509_crt_set_crq(cert_csr, csr)) {
	fprintf(stderr, "Cannot convert CSR to certificate.\n");
	exit(1);
    }
    
    if (gnutls_x509_crt_get_pk_rsa_raw(cert_issued, &mod1, &exp1) ||
	gnutls_x509_crt_get_pk_rsa_raw(cert_csr, &mod2, &exp2)) {
	fprintf(stderr, "Cannot extract public key from certificate.\n");
	exit(1);
    }
    
    if (mod1.size != mod2.size || memcmp(mod1.data, mod2.data, mod1.size)) {
	fprintf(stderr, "Certificate public key does not match CSR public key.\n");
	exit(1);
    }
    
    gnutls_free(mod1.data);
    gnutls_free(mod2.data);
    gnutls_free(exp1.data);
    gnutls_free(exp2.data);
    
    gnutls_x509_crq_deinit(csr);
    gnutls_x509_crt_deinit(cert_issued);
    gnutls_x509_crt_deinit(cert_csr);
}


void print_usage() {
    printf("This program is used to sign / verify a hash because openssl/gnutls\n");
    printf("cannot properly sign a file due to technical limitations .\n");
    printf("\n");
    printf("Usage:\n");
    printf("    sslsigntool sign <certificate_file> <priv_key_file> <data_file> <sig_file>\n");
    printf("    sslsigntool verify <certificate_file> <data_file> <sigfile>\n");
    printf("    sslsigntool check_match <csr_file> <certificate_file>\n");
    printf("\n");
    printf("    And remember kids: don't put more than 10000 bytes in your files.\n");
    printf("    The programmer was too lazy to loop reading a file.\n");
}

int main(int argc, char **argv) {

    if (argc < 2) {
	print_usage();
	exit(1);
    }
    
    gnutls_global_init();   
    
    if (! strcmp(argv[1], "sign")) {
	
	if (argc != 6) {
	    print_usage();
	    exit(1);
	}
	
	sign_file(argv[2], argv[3], argv[4], argv[5]);
    }
    
    else if (! strcmp(argv[1], "verify")) {
	
	if (argc != 5) {
	    print_usage();
	    exit(1);
	}
	
	verify_file(argv[2], argv[3], argv[4]);
    }
    
    else if (! strcmp(argv[1], "check_match")) {
	
	if (argc != 4) {
	    print_usage();
	    exit(1);
	}
	
	verify_csr_match_cert(argv[2], argv[3]);
    }
    
    else {
	print_usage();
	exit(1);
    }
    
    gnutls_global_deinit();   
    
    return 0;
}

