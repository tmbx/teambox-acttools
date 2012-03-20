/**
 * Copyright (C) 2010-2012 Opersys inc.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License, not any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* kpsinstalltool.cpp
 *
 * Copyright (C) 2007-2012 Opersys inc., All rights reserved.
 *
 * July 20th 2007
 */
 
 
/* Terminology:
 * Block: a part of a plaintext file.
 * Chunk: a part of an signed & encrypted file.
 *
 * Signature and encryption steps:
 * - Compute the hash of the file to sign.
 * - Sign the hash using the private key 2. Write it in the file.
 * - Generate a symmetric key.
 * - Encrypt the symmetric key with the public key 1. Write it in the file.
 * - Read the file to encrypt per 20MB blocks.
 * - Encrypt each block with the symmetric key. Write them in the file.
 *
 * Decryption and verification steps:
 * - Read the signature chunk from the output file.
 * - Read the encrypted symmetric key from the input file.
 * - Decrypt the symmetric key with the private key 1.
 * - Read each encrypted chunk from the input file.
 * - Decrypt each encrypted chunk with the symmetric key.
 * - Write each decrypted block in the output file.
 * - Compute the hash of the output file.
 * - Verify the signature of the hash with the public key 2.
 *
 * Signed & encrypted file format:
 * --- Encrypted chunk for KPS version 1.0 length XXXXXXXX ---
 * Binary chunck data.
 * --- Encrypted chunk for KPS version 1.0 length XXXXXXXX ---
 * Binary chunck data.
 * ...
 */

#include <stdio.h>
#include <string.h>
#include <ktools.h>
#include <kfs.h>
#include <gcrypt.h>
#include <tagcrypt.h>
#include <tagcryptgen.h>

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

/* This function writes the content of the kbuffer specified in the file
 * specified.
 */
static int write_kbuffer_to_file(char *path, kbuffer *buf) {
    int error = 0;
    FILE *file = NULL;
    
    do {
	error = kfs_fopen(&file, path, "wb");
	if (error) break;
	
	error = kfs_fwrite(file, buf->data, buf->len);
	if (error) break;
	
	error = kfs_fclose(&file, 0);
	if (error) break;
	
    } while (0);
    
    kfs_fclose(&file, 1);
    return error;
}

/** Keys are read in KCTL format:
 * start delim\n
 * ID\n
 * owner\n
 * ...key data...
 * end delim\n.
 * 
 * so here we skip start-delin, ID and owner, and end delim.  Then
 * remove all \n in key_data.
 */
static int sanitize_key_buffer(kbuffer *in_buf, kbuffer *out_buf) {
    uint8_t *c, *ptr, *key_data_start, *key_data_end;
    int nl_cnt = 0;

    /* Count 3 newlines. */
    ptr = in_buf->data;
    while (nl_cnt < 3 && (ptr = memchr(ptr, '\n', in_buf->len)) != NULL) {
        nl_cnt++;
        ptr++;
    }

    /* There is something wrong there. */
    if (ptr == NULL) return -1;
    else 
        key_data_start = ptr;

    /* Count 1 newline from the end. */
    ptr = memrchr(key_data_start, 
                  '\n', 
                  /* The -1 skips the last \n if there is one at the
                     end. */
                  in_buf->len - (key_data_start - (uint8_t *)in_buf->data) - 1);
    if (ptr == NULL) return -1;
    else
        key_data_end = ptr;

    /* Copy the key data in a new buffer, skipping the \n. */
    kbuffer_grow(out_buf, key_data_end - key_data_start);
    for (c = key_data_start; c < key_data_end; c++) 
        if (*c != '\n')
            kbuffer_write8(out_buf, *c);

    return 0;
}

/* This function reads the content of the file specified in the kbuffer
 * specified.
 */
static int read_kbuffer_from_file(char *path, kbuffer *buf) {
    int error = 0;
    FILE *file = NULL;
    uint64_t size;
    
    kbuffer_reset(buf);
    
    do {
	error = kfs_fopen(&file, path, "rb");
	if (error) break;
	
	error = kfs_fsize(file, &size);
	if (error) break;
	
	error = kfs_fread(file, kbuffer_write_nbytes(buf, size), size);
	if (error) break;
	
	error = kfs_fclose(&file, 0);
	if (error) break;
	
    } while (0);
    
    kfs_fclose(&file, 1);
    return error;
}

/* This function writes a block to the file specified. */
int write_block_to_file(FILE *file, kbuffer *block) {
    if (kfs_fwrite(file, block->data, block->len)) {
	append_error("cannot write block in file");
	return -1;
    }

    return 0;
}

/* This function reads a block from the file specified. */
int read_block_from_file(FILE *file, kbuffer *block, int len) {
    kbuffer_reset(block);

    if (kfs_fread(file, kbuffer_write_nbytes(block, len), len)) {
	append_error("cannot read block from file");
	return -1;
    }
    
    return 0;
}

/* This function writes a chunk to the encrypted file specified. */
int write_chunk_to_file(FILE *file, kbuffer *chunk) {
    char header[100];
    sprintf(header, "--- Encrypted chunk for KPS version 1.0 length %.8X ---\n", chunk->len);
    
    if (kfs_fwrite(file, header, strlen(header)) ||
        kfs_fwrite(file, chunk->data, chunk->len) ||
	kfs_fwrite(file, "\n", 1)) {
	append_error("cannot write chunk in file");
	return -1;
    }

    return 0;
}

/* This function reads a chunk from the installation file specified. */
int read_chunk_from_file(FILE *file, kbuffer *chunk) {
    char header[100];
    unsigned int len = strlen("--- Encrypted chunk for KPS version 1.0 length XXXXXXXX ---\n");
    unsigned int major, minor;
    header[len] = 0;
    
    kbuffer_reset(chunk);
    
    if (kfs_fread(file, header, len)) {
	append_error("cannot read chunk from file");
	return -1;
    }
    
    if (sscanf(header, "--- Encrypted chunk for KPS version %d.%d length %X ---\n", &major, &minor, &len) != 3) {
	set_error("cannot parse chunk in file");
	return -1;
    }
    
    if (major != 1 || minor != 0) {
	set_error("the input file is in format %d.%d and this program can only support format 1.0",
		  major, minor);
	return -1;
    }
    
    if (kfs_fread(file, kbuffer_write_nbytes(chunk, len), len) ||
	kfs_fread(file, header, 1)) {
	append_error("cannot read chunk from file");
	return -1;
    }
    
    return 0;
}

/* This functions loads a private key from the file specified. */
int load_priv_key_from_file(char *path, tagcrypt_skey **key) {
    int error = 0;
    kbuffer key_buf_kctl;
    kbuffer key_buf_b64;
    kbuffer key_buf_bin;
    
    kbuffer_init(&key_buf_b64);
    kbuffer_init(&key_buf_kctl);
    kbuffer_init(&key_buf_bin);
    
    do {
	error = read_kbuffer_from_file(path, &key_buf_kctl);
	if (error) break;

        error = sanitize_key_buffer(&key_buf_kctl, &key_buf_b64);
        if (error) break;
	
	error = kb642bin(&key_buf_b64, &key_buf_bin, 0);
	if (error) break;
	
	*key = tagcrypt_skey_new(&key_buf_bin);
	
	if (! *key) {
	    set_error("cannot load private key");
	    error = -1;
	    break;
	}
	
    } while (0);
    
    kbuffer_clean(&key_buf_b64);
    kbuffer_clean(&key_buf_kctl);
    kbuffer_clean(&key_buf_bin);
    
    return error;
}

/* This functions loads a public key from the file specified. */
int load_pub_key_from_file(char *path, tagcrypt_pkey **key) {
    int error = 0;
    kbuffer key_buf_b64;
    kbuffer key_buf_kctl;
    kbuffer key_buf_bin;
    
    kbuffer_init(&key_buf_b64);
    kbuffer_init(&key_buf_kctl);
    kbuffer_init(&key_buf_bin);
    
    do {
	error = read_kbuffer_from_file(path, &key_buf_kctl);
	if (error) break;
	
        error = sanitize_key_buffer(&key_buf_kctl, &key_buf_b64);
        if (error) break;

	error = kb642bin(&key_buf_b64, &key_buf_bin, 0);
	if (error) break;
	
	*key = tagcrypt_pkey_new(&key_buf_bin, 0);
	
	if (! *key) {
	    set_error("cannot load public key");
	    error = -1;
	    break;
	}
	
    } while (0);
    
    kbuffer_clean(&key_buf_b64);
    kbuffer_clean(&key_buf_kctl);
    kbuffer_clean(&key_buf_bin);
    
    return error;
}

/* This function serializes the symmetric key specified. */
int serialize_sym_key(tagcrypt_symkey *key, kbuffer *out) {
    kbuffer_reset(out);
    
    if (tagcrypt_symkey_serialize(key, out)) {
	set_error("cannot serialize symmetric key");
	return -1;
    }
    
    return 0;
}

/* This function deserializes a symmetric key from the buffer specified. */
int deserialize_sym_key(kbuffer *in, tagcrypt_symkey **key) {
    *key = tagcrypt_symkey_new_serialized(in);

    if (! *key) {
	set_error("cannot deserialize symmetric key");
	return -1;
    }
    
    return 0;
}

/* This function signs the data specified with the private key specified. */
int sign_data(kbuffer *in, kbuffer *out, tagcrypt_skey *key) {
    kbuffer_reset(out);
    
    if (tagcrypt_skey_sign(key, GCRY_MD_SHA256, in, out)) {
	set_error("cannot sign data"); 
	return -1;
    }
    
    return 0;
}

/* This function verifies the data specified with the public key specified. */
int verify_data(kbuffer *data, kbuffer *sig, tagcrypt_pkey *key) {
    
    if (tagcrypt_pkey_verify(key, GCRY_MD_SHA256, data, sig)) {
	set_error("the signature does not verify correctly");
	return -1;
    }
    
    return 0;
}

/* This function encrypts the data specified with the public key specified. */
int pub_key_encrypt(kbuffer *in, kbuffer *out, tagcrypt_pkey *key) {
    kbuffer_reset(out);
    
    if (tagcrypt_pkey_encrypt(key, in, out)) {
	set_error("cannot encrypt data with public key"); 
	return -1;
    }
    
    return 0;
}

/* This function decrypts the data specified with the private key specified. */
int priv_key_decrypt(kbuffer *in, kbuffer *out, tagcrypt_skey *key) {
    kbuffer_reset(out);
    
    if (tagcrypt_skey_decrypt(key, in, out)) {
	set_error("cannot decrypt data with private key");
	return -1;
    }
    
    return 0;
}

/* This function encrypts the data specified with the symmetric key specified. */
int sym_key_encrypt(kbuffer *in, kbuffer *out, tagcrypt_symkey *key) {
    kbuffer_reset(out);
    
    if (tagcrypt_symkey_encrypt(key, in, out)) {
	set_error("cannot encrypt data with symmetric key"); 
	return -1;
    }
    
    return 0;
}

/* This function decrypts the data specified with the symmetric key specified. */
int sym_key_decrypt(kbuffer *in, kbuffer *out, tagcrypt_symkey *key) {
    kbuffer_reset(out);
    
    if (tagcrypt_symkey_decrypt(key, in, out)) {
	set_error("cannot decrypt data with symmetric key");
	return -1;
    }
    
    return 0;
}

/* This function generates an asymmetric key pair. */
int generate_asym_key_pair(kbuffer *priv_key, kbuffer *pub_key, int64_t key_id) {
    int error = 0;
    kbuffer_reset(priv_key);
    kbuffer_reset(pub_key);
   
    error = tagcrypt_gen_public_secret(pub_key, priv_key, key_id, 2048);
    if (error) {
	append_error("cannot generate asymmetric key pair");
	return -1;
    }
    
    return 0;
}

/* This function generates a symmetric key. */
int generate_sym_key(tagcrypt_symkey **key) {
    *key = tagcrypt_symkey_new();
    
    if (*key == NULL) {
	append_error("cannot generate symmetric key");
	return -1;
    }
    
    return 0;
}

/* This function obtains the hash of the file specified. */
int get_file_hash(char *file_path, kbuffer *hash) {
    int error = 0;
    FILE *file = NULL;
    kstr command;
    
    kstr_init(&command);
    kstr_sf(&command, "sha256sum %s", file_path);
    
    kbuffer_reset(hash);
    
    /* Try. */
    do {
	file = popen(command.data, "r");
	
	if (file == NULL) {
	    set_error("cannot execute command '%s'", command.data);
	    error = -1;
	    break;
	}
	
	error = kfs_fread(file, kbuffer_write_nbytes(hash, 64), 64);
	if (error) break;
	
	if (pclose(file)) {
	    file = NULL;
	    set_error("cannot execute command '%s'", command.data);
	    error = -1;
	    break;
	}
	
	file = NULL;
	
    } while (0);
    
    if (error) {
	append_error("cannot compute hash of file");
    }
    
    if (file) fclose(file);
    kstr_clean(&command);
    
    return error;
}

/* This function signs and encrypts the file specified. */
int sign_encrypt_file(char *sign_key_path, char *enc_key_path, char *input_path, char *output_path) {
    int error = -1;
    uint64_t total_len = 0;
    int read_len = 0;
    kbuffer block;
    kbuffer chunk;
    tagcrypt_symkey *symkey = NULL;
    tagcrypt_skey *skey = NULL;
    tagcrypt_pkey *pkey = NULL;
    FILE *input_file = NULL;
    FILE *output_file = NULL;
    
    kbuffer_init(&block);
    kbuffer_init(&chunk);
    
    do {
	/* Load the signature key and the encryption key. */
	if (load_priv_key_from_file(sign_key_path, &skey)) break;
	if (load_pub_key_from_file(enc_key_path, &pkey)) break;
	
	/* Open the files, get the length of the input file. */
	if (kfs_fopen(&input_file, input_path, "rb")) break;
	if (kfs_fopen(&output_file, output_path, "wb")) break;
	if (kfs_fsize(input_file, &total_len)) break;
	
        /* Compute the hash of the file, sign it and write it in the file. */
	if (get_file_hash(input_path, &block)) break;
	if (sign_data(&block, &chunk, skey)) break;
	if (write_chunk_to_file(output_file, &chunk)) break;
	
        /* Generate a symmetric key, serialize it, encrypt it with the public
         * key and write it in the file.
         */
	if (generate_sym_key(&symkey)) break;
	if (serialize_sym_key(symkey, &block)) break;
	if (pub_key_encrypt(&block, &chunk, pkey)) break;
	if (write_chunk_to_file(output_file, &chunk)) break;
	
        /* Read the file in 20MB blocks. Encrypt each block with the symmetric
         * key and write it in the file.
         */
	while (read_len != total_len) {
	    int block_len = MIN(total_len - read_len, 20*1024*1024);
	    read_len += block_len;
	    if (read_block_from_file(input_file, &block, block_len)) break;
	    if (sym_key_encrypt(&block, &chunk, symkey)) break;
	    if (write_chunk_to_file(output_file, &chunk)) break;
	}
	
	/* Close the files. */
	if (kfs_fclose(&input_file, 0)) break;
	if (kfs_fclose(&output_file, 0)) break;
	
	error = 0;
	
    } while (0);
    
    if (error) {
	fprintf(stderr, "cannot sign and encrypt file: %s\n", get_error());
    }
	
    tagcrypt_symkey_destroy(symkey);
    tagcrypt_skey_destroy(skey);
    tagcrypt_pkey_destroy(pkey);
    kfs_fclose(&input_file, 1);
    kfs_fclose(&output_file, 1);
    kbuffer_clean(&block);
    kbuffer_clean(&chunk);
    
    return error;
}

/* This function decrypts and verifies the file specified. */
int decrypt_verify_file(char *sign_key_path, char *enc_key_path, char *input_path, char *output_path) {
    int error = -1;
    kbuffer block;
    kbuffer chunk;
    kbuffer hash_sig;
    tagcrypt_symkey *symkey = NULL;
    tagcrypt_skey *skey = NULL;
    tagcrypt_pkey *pkey = NULL;
    FILE *input_file = NULL;
    FILE *output_file = NULL;
    
    kbuffer_init(&block);
    kbuffer_init(&chunk);
    kbuffer_init(&hash_sig);
    
    do {
	/* Load the signature key and the encryption key. */
	if (load_priv_key_from_file(enc_key_path, &skey)) break;
	if (load_pub_key_from_file(sign_key_path, &pkey)) break;
	
	/* Open the files. */
	if (kfs_fopen(&input_file, input_path, "rb")) break;
	if (kfs_fopen(&output_file, output_path, "wb")) break;
	
        /* Read the hash signature from the file. */
	if (read_chunk_from_file(input_file, &hash_sig)) break;
	
        /* Read the symmetric key from the input file, decrypt it with the
         * private key and deserialize it.
         */
	if (read_chunk_from_file(input_file, &chunk)) break;
	if (priv_key_decrypt(&chunk, &block, skey)) break;
	if (deserialize_sym_key(&block, &symkey)) break;
	
        /* Read the remaining chunks from the file, decrypt them with the
         * symmetric key, and write them to the output file.
         */
	while (! feof(input_file)) {
	    if (read_chunk_from_file(input_file, &chunk)) break;
	    if (sym_key_decrypt(&chunk, &block, symkey)) break;
	    if (write_block_to_file(output_file, &block)) break;
	}
	
	/* Close the files. */
	if (kfs_fclose(&input_file, 0)) break;
	if (kfs_fclose(&output_file, 0)) break;
	
        /* Compute the hash of the file, and verify it against the hash
         * signature using with public key.
         */
	if (get_file_hash(output_path, &block)) break;
	if (verify_data(&block, &hash_sig, pkey)) break; 
	
	error = 0;
	
    } while (0);
    
    if (error) {
	fprintf(stderr, "cannot decrypt and verify file: %s\n", get_error());
    }
	
    tagcrypt_symkey_destroy(symkey);
    tagcrypt_skey_destroy(skey);
    tagcrypt_pkey_destroy(pkey);
    kfs_fclose(&input_file, 1);
    kfs_fclose(&output_file, 1);
    kbuffer_clean(&block);
    kbuffer_clean(&chunk);
    kbuffer_clean(&hash_sig);
    
    return error;
}

/* This function generates an asymmetric key pair and writes it in the files
 * specified.
 */
int generate_key_pair_file(char *priv_key_path, char *pub_key_path, char *key_id_str) {
    int error = 0;
    int64_t key_id = 0;
    char *end = NULL;
    kbuffer priv_key;
    kbuffer priv_key_data;
    kbuffer pub_key;
    kbuffer pub_key_data;
    
    kbuffer_init(&priv_key_data);
    kbuffer_init(&pub_key_data);
    kbuffer_init(&priv_key);
    kbuffer_init(&pub_key);
    
    /* Try. */
    do {
	key_id = strtoll(key_id_str, &end, 10);
	
	if (! *key_id_str || *end || ! key_id) {
	    set_error("invalid key ID specified ('%s')", key_id_str);
	    error = -1;
	    break;
	}

        char start_sig_pkey[] = "--- START SIGNATURE PUBLIC KEY ---\n\n\n";
        char end_sig_pkey[] = "\n--- END SIGNATURE PUBLIC KEY ---\n";

        char start_sig_skey[] = "--- START SIGNATURE PRIVATE KEY ---\n\n\n";
        char end_sig_skey[] = "\n--- END SIGNATURE PRIVATE KEY ---\n";

	error = generate_asym_key_pair(&priv_key_data, &pub_key_data, key_id);
	if (error) break;

        kbuffer_write_cstr(&priv_key, start_sig_skey);
        kbuffer_write_cstr(&pub_key, start_sig_pkey);

        kbuffer_write_buffer(&priv_key, &priv_key_data);
        kbuffer_write_buffer(&pub_key, &pub_key_data);

        kbuffer_write_cstr(&priv_key, end_sig_skey);
        kbuffer_write_cstr(&pub_key, end_sig_pkey);
        
	error = write_kbuffer_to_file(priv_key_path, &priv_key);
	if (error) break;
	
	error = write_kbuffer_to_file(pub_key_path, &pub_key);
	if (error) break;
	
    } while (0);
    
    if (error) {
	fprintf(stderr, "cannot generate keys: %s\n", get_error());
    }
    
    kbuffer_clean(&priv_key);
    kbuffer_clean(&pub_key);
    
    return error;
}

void print_usage() {
    printf("This program is used to sign and encrypt a file using the keys specified.\n"
           "Inversely the program can also decrypt and verify the encrypted file.\n"
           "For convenience the program can also generate a key pair having the ID\n"
           "specified.\n"
	   "\n"
           "Usage:\n"
           "    kpsinstalltool sign_encrypt <priv_sign_key> <pub_enc_key>\n"
	   "                                <input_file> <output_file>\n"
           "    kpsinstalltool decrypt_verify <pub_sign_key> <priv_enc_key>\n"
	   "                                  <input_file> <output_file>\n"
	   "    kpsinstalltool gen_key <priv_sign_key> <pub_sign_key> <key_id>\n");
}

int main(int argc, char **argv) {
    int error = 0;
    
    ktools_initialize();
    tagcrypt_init();
    kstr_init(&last_error_msg);
    
    if (argc < 2) {
	print_usage();
	error = -1;
    }
    
    else if (! strcmp(argv[1], "sign_encrypt") && argc == 6) {
	error = sign_encrypt_file(argv[2], argv[3], argv[4], argv[5]);
    }
    
    else if (! strcmp(argv[1], "decrypt_verify") && argc == 6) {
	error = decrypt_verify_file(argv[2], argv[3], argv[4], argv[5]);
    }
    
    else if (! strcmp(argv[1], "gen_key") && argc == 5) {
	error = generate_key_pair_file(argv[2], argv[3], argv[4]);
    }
     
    else {
	print_usage();
	error = -1;
    }
    
    kstr_clean(&last_error_msg);
    ktools_finalize();
    
    return error ? 1 : 0;
}

