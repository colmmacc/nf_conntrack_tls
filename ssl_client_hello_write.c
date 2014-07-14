#include <stdlib.h>
#include <string.h>
#include "ssl_client_hello.h"

/* Consume a byte from the data stream
 */
#define WROTE_BYTES( len )    do { if (data_len < len) { *message = "Client hello is too long for buffer"; return -1; } data_ptr += (len); data_len -= (len); } while(0);
#define WROTE_BYTE()          WROTE_BYTES( 1 ) 

/*
 * Parse an SSL2 Client Hello message
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
int ssl2_client_hello_write(struct ssl2_client_hello_data *hello_data, uint8_t * data_ptr, uint32_t data_len, char **message)
{
	uint16_t challenge_len;

	if (hello_data == NULL) {
		*message = "NULL hello_data passed to ssl2_client_hello_write";
		return -1;
	}

        *data_ptr = SSL_CLIENT_HELLO;
	WROTE_BYTE();

	*data_ptr = hello_data->client_version[0];
	WROTE_BYTE();

	*data_ptr = hello_data->client_version[1];
	WROTE_BYTE();

	hello_data->cipher_specs_len = (*data_ptr << 8);
	WROTE_BYTE();

	hello_data->cipher_specs_len |= *data_ptr;
	WROTE_BYTE();

	if (hello_data->cipher_specs_len % 3) {
		*message = "SSL2 Client Hello record has invalid cipher spec length";
		return -1;
	}

	if (hello_data->cipher_specs_len > MAX_CIPHER_SPECS_LEN) {
		*message = "SSL2 Client Hello record has too large a cipher spec length";
		return -1;
	}

	hello_data->session_id_len = (*data_ptr << 8);
	WROTE_BYTE();

	hello_data->session_id_len |= *data_ptr;
	WROTE_BYTE();

	if (hello_data->session_id_len != 0 && hello_data->session_id_len != 16) {
		*message = "SSL2 Client Hello record has invalid session id length";
		return -1;
	}

	challenge_len = (*data_ptr << 8);
	WROTE_BYTE();

	challenge_len |= *data_ptr;
	WROTE_BYTE();

	if (challenge_len < 16 || challenge_len > 32) {
		*message = "SSL2 Client Hello record has invalid session id length";
		return -1;
	}

	/* Check the record is long enough to contain the data it claims to
	 * contain 
	 */

	if (data_len < ((hello_data->cipher_specs_len * 3) + hello_data->session_id_len + challenge_len)) {
		*message = "SSL2 Client Hello record is too short";
		return -1;
	}

	/* Copy the cipher specs */
	if (memcpy(hello_data->cipher_specs, data_ptr, hello_data->cipher_specs_len * 3) != hello_data->cipher_specs) {
		*message = "SSL2 Client Hello record encountered memcpy error";
		return -1;
	}
	WROTE_BYTES(hello_data->cipher_specs_len * 3);

	/* Copy the session id */
	if (memcpy(hello_data->session_id, data_ptr, hello_data->session_id_len) != hello_data->session_id) {
		*message = "SSL2 Client Hello record encountered memcpy error";
		return -1;
	}
	WROTE_BYTES(hello_data->session_id_len);

	/* Per Appendix E.2 of the TLS RFCs, the challenge should be padded with
	 * leading zeroes.
	 */
	if (challenge_len < 32) {
		if (memset(hello_data->challenge, 0, 32 - challenge_len) != hello_data->challenge) {
			*message = "SSL2 Client Hello record encountered memset error";
			return -1;
		}
	}

	/* Copy the challenge */
	if (memcpy(hello_data->challenge + (32 - challenge_len), data_ptr, challenge_len) !=
	    hello_data->challenge + (32 - challenge_len)) {
		*message = "SSL2 Client Hello record encountered memcpy error";
		return -1;
	}
	WROTE_BYTES(challenge_len);

	/* The SSL2 Draft does not make it clear if the SSL record can or should
	 * not contain any extraneous data.
	 */

	return 0;
}
