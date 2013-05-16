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

/* verifyorgcert.c
 *
 * Copyright (C) 2007-2012 Opersy inc., All rights reserved.
 *
 * August 23th 2007
 */
 
#include <stdio.h>
#include <string.h>
#include <ktools.h>
#include <kfs.h>
#include <getopt.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#if defined(LIBGNUTLS_VERSION_MAJOR) && LIBGNUTLS_VERSION_MINOR >= 2
#include <gnutls/compat.h>
#endif

/* Number of days after the activation date of an organization's certificate for
 * which the certficate is considered valid.
 */
#define MAX_DAY_AFTER_CERT_ACT   90

/* Program options. */
struct pgm_option {
    char *org_cert_path;
    char *ca_dir_path;
    int print_level;
    int verify;
};

/* Global kstr containing the current error message. */
kstr last_error_msg;

/* This function updates the last_error_msg string from the current error stack. */
static void update_last_error_msg() { struct kerror *error_instance = kerror_get_current();
    int i;
    
    kstr_reset(&last_error_msg);

    if (error_instance->stack.size == 0) {
        kstr_assign_cstr(&last_error_msg, "unknown error");
    }
    
    else {
	for (i = error_instance->stack.size - 1; i >= 0; i--) {
	    struct kerror_node *node = (struct kerror_node *) karray_get(&error_instance->stack, i);
	    
	    if (i != error_instance->stack.size - 1) {
		kstr_append_cstr(&last_error_msg, ": ");
	    }
	    
	    kstr_append_kstr(&last_error_msg, &node->text);
	}
    }
}

/* This macro sets the thread-local error message. All previously stacked
 * messages are cleared.
 */
#define set_error(...) \
    kerror_reset(); \
    kerror_push(kerror_node_new(__FILE__, __LINE__, __FUNCTION__, 1, 0, __VA_ARGS__))
    
/* This macro appends an error message to the thread-local error messages
 * already set.
 */
#define append_error(...) \
    kerror_push(kerror_node_new(__FILE__, __LINE__, __FUNCTION__, 1, 0, __VA_ARGS__))
 
/* This function returns a pointer to a C string containing the current error
 * message. The string is valid until the next call to this function.
 */
static char * get_error() {
    update_last_error_msg();
    return last_error_msg.data;
}

/* This function deletes the kstr present in the array specified, then it resets
 * the size of the array.
 */
void clear_kstr_array(karray *array) {
    int i;

    for (i = 0; i < array->size; i++) {
    	kstr_destroy((kstr *) array->data[i]);
    }
	
    array->size = 0;
}

/* This function frees the memory associated to a certificate. */
void cert_clean(gnutls_x509_crt cert) {
    if (cert) {
	gnutls_x509_crt_deinit(cert);
    }
}

/* This function deletes the certificates present in the array specified, then
 * it resets the size of the array.
 */
void clear_cert_array(karray *array) {
    int i;

    for (i = 0; i < array->size; i++) {
	cert_clean((gnutls_x509_crt) array->data[i]);
    }
	
    array->size = 0;
}

/* This function reads the certificate file specified and creates the
 * corresponding certificate object.
 * It returns -1 on failure, 0 otherwise.
 */
int read_cert_file(char *path, gnutls_x509_crt *cert) {
    int error = -1;
    int r;
    int file_size;
    char *file_data = NULL;
    FILE *file = NULL;
    gnutls_datum tls_data;
    
    *cert = NULL;
    
    /* Try. */
    do {
	/* Read the certificate file in memory. */
	if (kfs_fopen(&file, path, "rb")) break;
	if (kfs_fsize(file, &file_size)) break;
	file_data = (char *) kmalloc(file_size);
	if (kfs_fread(file, file_data, file_size)) break;
	
	/* Initialize and import the certificate. */
	tls_data.data = file_data;
	tls_data.size = file_size;

	r = gnutls_x509_crt_init(cert);
	if (r) {
	    set_error("cannot initialize certificate: %s", gnutls_strerror(r));
	    break;
	}
	
	r = gnutls_x509_crt_import(*cert, &tls_data, GNUTLS_X509_FMT_PEM);
	if (r) {
	    set_error("cannot import certificate: %s", gnutls_strerror(r));
	    break;
	}
	
	error = 0;
	
    } while (0);
    
    kfree(file_data);
    kfs_fclose(&file, 1);
    
    if (error) {
	if (cert) {
	    cert_clean(*cert);
	    *cert = NULL;
	}
	
	append_error("cannot read certificate %s", path);
    }
    
    return error;
}

/* This function loads the CA certificates contained in the directory specified.
 * The loaded certificates are placed in 'cert_array'.
 * It returns -1 on failure, 0 otherwise.
 */
int load_ca_dir(char *ca_dir_path, karray *cert_array) {
    int error = 0; 
    int i;
    gnutls_x509_crt cert;
    karray file_array;
    kstr file_path;
    
    karray_init(&file_array);
    kstr_init(&file_path);
    karray_reset(cert_array);
    
    /* Try. */
    do {
	/* Get the file list. */
	error = kfs_ls(ca_dir_path, &file_array);
	if (error) break;
	
	/* Pass each file. */
	for (i = 0; i < file_array.size; i++) {
	    kstr *file_name = (kstr *) file_array.data[i];
	    kstr_sf(&file_path, "%s/%s", ca_dir_path, file_name->data);
	    
	    /* The file is a regular file. */
	    if (kfs_regular(file_path.data)) {
		
		/* Load and store the certificate. */
		error = read_cert_file(file_path.data, &cert);
		if (error) break;
		karray_push(cert_array, cert);
	    }
	}
	
	if (error) break;
	
    } while (0);
    
    clear_kstr_array(&file_array);
    karray_clean(&file_array);
    kstr_clean(&file_path);
    if (error) clear_cert_array(cert_array);
    
    return error;
}

/* This function verifies the certificate specified against the list of CA
 * certificates specified, and checks other basic constraints.
 * It returns -1 on failure, 0 otherwise.
 */
int verify_cert(gnutls_x509_crt cert, karray *ca_array) {
    unsigned int status;
    int r = gnutls_x509_crt_verify(cert, 
                                   (gnutls_x509_crt *) ca_array->data,
                                   ca_array->size,
                                   GNUTLS_VERIFY_DISABLE_CA_SIGN,
                                   &status);
    time_t now = time(NULL);
    time_t act_time, expire_time, delta_time;
    
    /* Verify the certificate authenticity. */
    if (r) {
	set_error("cannot verify certificate: %s", gnutls_strerror(r));
	return -1;
    }
    
    if (status) {
	if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
	    set_error("the certificate was signed by an authority that we do not trust. "
		      "Ask an administrator to investigate the matter: the certificate might be valid");
	}
	
	else if (status & GNUTLS_CERT_REVOKED) {
	    set_error("the certificate has been revoked");
	}
	
	else if (status & GNUTLS_CERT_INSECURE_ALGORITHM) {
	    set_error("the certificate was signed using an insecure algorithm");
	}
	
	else if (status & GNUTLS_CERT_INVALID) {
	    set_error("the signature of the certificate is invalid");
	}
	
	else {
	    set_error("unknown verification error (%d)", status);
	}
	
	return -1;
    }
    
    /* Verify the expiration date. */
    act_time = gnutls_x509_crt_get_activation_time(cert);
    expire_time = gnutls_x509_crt_get_expiration_time(cert);
    delta_time = now - act_time;
    
    if (act_time == (time_t) -1 || expire_time == (time_t) -1) {
	set_error("cannot get certificate activation/expiration dates");
	return -1;
    }
    
    if (act_time > now) {
	set_error("the certificate is not yet activated (activation date is %s UTC)", asctime(gmtime(&act_time)));
	return -1;
    }
    
    if (expire_time < now) {
	set_error("the certificate is expired (expiration date is %s UTC)", asctime(gmtime(&expire_time)));
	return -1;
    }

    if (delta_time > MAX_DAY_AFTER_CERT_ACT * 24 * 60 * 60) {
	set_error("the certificate was issued too long ago (%d days old)", delta_time / (24 * 60 * 60));
	return -1;
    }
    
    printf("Certificate is valid.\n");
    
    return 0;
}


/* Helper function for print_cert_basic_info(). */
void get_cert_basic_info_field(char *buf, gnutls_x509_ava_st *ava_st) {
    int last = MIN(199, ava_st->value.size);
    memcpy(buf, ava_st->value.data, last);
    buf[last] = 0;
}

/* This function prints some basic information about the specified certificate.
 * It returns -1 on failure, 0 otherwise.
 */
int print_cert_basic_info(gnutls_x509_crt cert) {
    char dn[200], issuer_dn[200];
    char country[200] = { 0 }, state[200] = { 0 }, location[200] = { 0 }, org_name[200] = { 0 }, ou_name[200] = { 0 },
         common_name[200] = { 0 };
    size_t dn_s = 200, issuer_dn_s = 200;
    int rdn = 0;
    unsigned int key_usage, critical;
    gnutls_x509_ava_st ava_st;
    gnutls_x509_dn_t subject;
    time_t act_time, expire_time;
    
    /* Extract the information. */
    if (gnutls_x509_crt_get_dn(cert, dn, &dn_s) ||
	gnutls_x509_crt_get_issuer_dn(cert, issuer_dn, &issuer_dn_s) ||
	gnutls_x509_crt_get_subject(cert, &subject) ||
	(act_time = gnutls_x509_crt_get_activation_time(cert)) == (time_t) -1 ||
	(expire_time = gnutls_x509_crt_get_expiration_time(cert)) == (time_t) -1) {
	
	set_error("cannot print certificate info");
	return -1;
    }
    
    if (gnutls_x509_crt_get_key_usage(cert, &key_usage, &critical)) {
	key_usage = 0;
    }
    
    while (! gnutls_x509_dn_get_rdn_ava(subject, rdn++, 0, &ava_st)) {
	if (! strcmp(ava_st.oid.data, GNUTLS_OID_X520_COUNTRY_NAME)) get_cert_basic_info_field(country, &ava_st);
	if (! strcmp(ava_st.oid.data, GNUTLS_OID_X520_ORGANIZATION_NAME)) get_cert_basic_info_field(org_name, &ava_st);
	if (! strcmp(ava_st.oid.data, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME))
								    get_cert_basic_info_field(ou_name, &ava_st);
	if (! strcmp(ava_st.oid.data, GNUTLS_OID_X520_COMMON_NAME)) get_cert_basic_info_field(common_name, &ava_st);
	if (! strcmp(ava_st.oid.data, GNUTLS_OID_X520_LOCALITY_NAME)) get_cert_basic_info_field(location, &ava_st);
	if (! strcmp(ava_st.oid.data, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME))
								    get_cert_basic_info_field(state, &ava_st);
    }
    
    printf("============ Certificate summary ============\n");
    printf("Country:           %s\n", country);
    printf("State:             %s\n", state);
    printf("Location:          %s\n", location);
    printf("Organization:      %s\n", org_name);
    printf("Organization unit: %s\n", ou_name);
    printf("Domain name:       %s\n", common_name);
    printf("\n");
    printf("Activation (UTC):  %s", asctime(gmtime(&act_time)));
    printf("Expiration (UTC):  %s", asctime(gmtime(&expire_time)));
    printf("Digital signature: %s\n", (key_usage & GNUTLS_KEY_DIGITAL_SIGNATURE) ? "set" : "not set");
    printf("\n");
    printf("DN: %s\n", dn);
    printf("\n");
    printf("Issuer DN: %s\n", issuer_dn);
    printf("=============================================\n");
    
    return 0;
}

/* This function prints all the information available about the specified
 * certificate.
 * It returns -1 on failure, 0 otherwise.
 */
int print_cert_full_info(gnutls_x509_crt cert) {
    gnutls_datum_t out = { NULL, 0 };
    int error = gnutls_x509_crt_print(cert, GNUTLS_X509_CRT_FULL, &out);
    
    if (! error) {
	printf("%s\n", out.data);
    }
    
    else {
	set_error("cannot print certificate: %s", gnutls_strerror(error));
	error = -1;
    }
    
    gnutls_free(out.data);
    
    return error;
}

/* This function performs the requested operations on the specified
 * organization's certificates.
 * It returns -1 on failure, 0 otherwise.
 */
int handle_org_cert(char *org_cert_path, char *ca_dir_path, int print_level, int verify) {
    int error = -1;
    gnutls_x509_crt cert = NULL;
    karray ca_array;
    
    karray_init(&ca_array);
     
    /* Try. */
    do {
	/* Read the certificate. */
	if (read_cert_file(org_cert_path, &cert)) break;
	
	/* Print some information about the certificate. */
	if (print_level == 1) {
	    if (print_cert_basic_info(cert)) break;
	}
	
	else if (print_level == 2) {
	    if (print_cert_full_info(cert)) break;
	}
	
	/* Verify the certificate. */
	if (verify) {
	    if (load_ca_dir(ca_dir_path, &ca_array)) break;
	    if (verify_cert(cert, &ca_array)) break;
	}
	
	error = 0;
	
    } while (0);
    
    clear_cert_array(&ca_array);
    karray_clean(&ca_array);
    cert_clean(cert);
    
    if (error) {
	fprintf(stderr, "Error: %s.\n", get_error());
    }
    
    return error;
}

void print_usage() {
    printf("This program is used to check the validity of an organization's certificate.\n");
    printf("\n");
    printf("Usage:\n");
    printf("    verifyorgcert [-o <org cert path>] [-d <ca dir path>] [-p -P -v -h]\n");
    printf("\n");
    printf("-o <path>         Path to the organization's certificate.\n");
    printf("-d <path>         Path to the directory containing the CA certificates we trust.\n");
    printf("-p                Print basic information about the organization's certificate.\n");
    printf("-P                Print full information about the organization's certificate.\n");
    printf("-v                Verify the organization's certificate.\n");
    printf("-h                Print this help message and exit.\n");
}

/* This function parses the command line arguments. It returns 0 if the program
 * should keep going, -1 if the program should exit with a failure code and -2
 * if the program should exit with a success code.
 */
int handle_cmd_line(int argc, char **argv, struct pgm_option *opt) {

    while (1) {
	int cmd = getopt(argc, argv, "o:d:pPvh");

	if (cmd == '?' || cmd == ':') {
	    print_usage();
	    return -1;
	}
	
	else if (cmd == 'h') {
	    print_usage();
	    return -2;
	}
	
	else if (cmd == 'o') {
	    opt->org_cert_path = optarg;
	}
	
	else if (cmd == 'd') {
	    opt->ca_dir_path = optarg;
	}
	
	else if (cmd == 'p') {
	    opt->print_level = 1;
	}
	
	else if (cmd == 'P') {
	    opt->print_level = 2;
	}
	
	else if (cmd == 'v') {
	    opt->verify = 1;
	}
	
	else if (cmd == -1) {
	    break;
	}

	else {
	    assert(0);
	}
    }
    
    if (opt->org_cert_path == NULL ||
        (opt->verify && opt->ca_dir_path == NULL) ||
	(! opt->print_level && ! opt->verify)) {
	
	print_usage();
	return -1;
    }
    
    return 0;
}
    
int main(int argc, char **argv) {
    int error = 0;
    struct pgm_option opt = { NULL, NULL, 0, 0 };
    
    error = handle_cmd_line(argc, argv, &opt);
    if (error == -1) return 1;
    if (error == -2) return 0;
    
    ktools_initialize();
    kstr_init(&last_error_msg);
    gnutls_global_init();   
    
    error = handle_org_cert(opt.org_cert_path, opt.ca_dir_path, opt.print_level, opt.verify) ? 1 : 0;
    
    gnutls_global_deinit();   
    kstr_clean(&last_error_msg);
    ktools_finalize();

    return error;
}

