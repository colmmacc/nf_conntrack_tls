#pragma once

#ifdef __KERNEL__
#include <linux/module.h>
#else
#include <stdint.h>
#endif

/* Per http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html C.2 */
#define SSL_CLIENT_HELLO    1

/* Cipher specs are 3 bytes each, the maximum size of a hello record is
 * 65536 bytes. Use a simplistic over-estimate assuming the entire record
 * was nothing but cipher specs.
 */
#define MAX_CIPHER_SPECS_LEN 21846

/* 
 * An SSL2 Client Hello message has the format:
 *
 *  Bytes     0-1: Client version 
 *  Bytes     2-3: Cipher specs length (CSL)
 *  Bytes     4-5: Session ID length   (SIL)
 *  Bytes     6-7: Challenge-length    (CHL)
 *  Bytes   8-CSL: Cipher specs
 *  Bytes CSL-SIL: Session ID length
 *  Bytes SIL-CHL: Challenge
 *
 */
struct ssl2_client_hello_data {

	/* The version advertised by the client */
	uint8_t client_version[2];

	/* The length of the cipher specifications */
	uint16_t cipher_specs_len;

	/* The session id length */
	uint16_t session_id_len;

	/* Maximum number of cipher specs */
	uint8_t cipher_specs[MAX_CIPHER_SPECS_LEN][3];

	/* The session id presended by the client */
	uint8_t session_id[16];

	/* The challenge  */
	uint8_t challenge[32];
};

/*
 * Read an SSL2 Client Hello message
 *
 * Parameters:
 *  hello_data          Pointer to the hello data structure to be filled
 *  data_ptr            pointer to the data stream to parse
 *  data_len            how much data is there to parse
 *  message             if we encounter an error, will be updated to point to
 *                      an error message
 *
 * Return:
 *     0   No problem encountered
 *    -1   A problem was encountered parsing the client hello
 */
extern int ssl2_client_hello_read(struct ssl2_client_hello_data *hello_data, uint8_t * data_ptr, uint32_t data_len,
		                  char **message);

/*
 * Read an SSL2 Client Hello message
 *
 * Parameters:
 *  hello_data          Pointer to the hello data structure to be filled
 *  data_ptr            pointer to the data stream to parse
 *  data_len            how much data is there to parse
 *  message             if we encounter an error, will be updated to point to
 *                      an error message
 *
 * Return:
 *   >=0   The number of bytes written
 *    -1   A problem was encountered parsing the client hello
 */
extern int ssl2_client_hello_write(struct ssl2_client_hello_data *hello_data, uint8_t * data_ptr, uint32_t data_len,
			           char **message);
