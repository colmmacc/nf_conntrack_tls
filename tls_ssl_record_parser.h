#pragma once

#ifdef __KERNEL__
#include <linux/module.h>
#else
#include <stdint.h>
#endif

/* Per http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml */
#define MINIMUM_TLS_CONTENT_TYPE    20
#define MAXIMUM_TLS_CONTENT_TYPE    24
#define HANDSHAKE_TLS_CONTENT_TYPE  22
#define HEARTBEAT_TLS_CONTENT_TYPE  24
#define HEARTBEAT_TLS_MINIMUM_SIZE  19

/* Per http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html C.2 */
#define SSL_CLIENT_HELLO    1
#define SSL_SERVER_HELLO    4
#define SSL_CLIENT_MASTER_KEY 2

/* 
 * The outermost layer of an TLS connection consists of a sequence
 * of records, one after another. Each record includes a length field,
 * so we know when to expect the next record.
 *
 * An SSL2 connection is a little different, it has its own, incompatible,
 * record layer. So we need to support both.
 *
 * A TLS/SSL record is described in RFC5246 and looks like;
 *
 *  Byte     0:   The SSL record type
 *  Byte   1-2:   SSL version
 *  Byte   3-4:   The length of the data
 *  Byte 5-N+5:   That data
 *
 * An SSL2 record is described in:
 * http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html
 * and is modal. The record format is a little different, depending on whether
 * the first two bits are set.
 *
 * If 0x80 is set in the first byte, then:
 *
 *  Bytes   0-1:  The length of the record (sort of)
 *  Bytes 2-N+2:  The record data
 *      
 * If 0x80 is not set and 0x40 is set, then the format is:
 *
 *  Bytes   0-1:  The length of the record (sort of)
 *  Byte      2:  Length of the padding data
 *  Bytes 3-N+3:  The record data
 *  Bytes N+3+P:  The padding data
 *
 * Why "sort of"? In SSL2 We have to mask out the first bit, if it is set, or 
 * first two bits if the first bit is not set, to arrive at the real length. 
 *
 * It's also valid for clients to negotiate upwards, e.g. from SSL2 to TLS, so 
 * both kinds of records may occur on the same session.
 *
 * Since any of these fields could occur right at a packet boundary, or even
 * split across two packets, we use a small state machine to record where we
 * are in the record stream handling. 
 *
 * In this module, those states are;
 *
 *      EXPECTING_NEXT_RECORD,
 *      READING_TLS_RECORD_HEADER,
 *      READING_SSL_RECORD_HEADER,
 *      READING_SSL_PADDED_RECORD_HEADER,
 *      READING_TLS_HEARTBEAT_RECORD,
 *      READING_ENCRYPTED_RECORD,
 *      READING_OPAQUE_RECORD 
 *
 * SSL2 records go through the following states transitions:
 *
 *      EXPECTING_NEXT_RECORD
 *      READING_SSL_RECORD_HEADER | READING_SSL_PADDED_RECORD_HEADER
 *      READING_ENCRYPTED_RECORD | READING_OPAQUE_RECORD
 *
 * TLS records go through these state transitions:
 *
 *      EXPECTING_NEXT_RECORD
 *      EXPECTING_TLS_RECORD_HEADER
 *      READING_ENCRYPTED_RECORD | READING_OPAQUE_RECORD
 *
 * We have opaque and clear records. If the record type is opaque, it should
 * look random, and we check to see if it looks suspicuous. The clear records 
 * we expect to contain plaintext, and give them a pass. Additionally we also 
 * handle the heartbeat record type explicitly, and check for symmetry 
 * between heartbeast requests and responses.
 *
 * One more note:  There can be more than one "inner" messages per "outer"
 * record, but a single inner message may also span multiple outer messages,
 * making it neccessary to couple inner and outer state machines in an 
 * unnatural way. 
 */
struct tls_state {

	/* The state machine tracks both sides of a connection.
	 * Each element is a 2-sized array, and the relevant
	 * indexes are ...
	 */
#define CLIENT_TO_SERVER 0
#define SERVER_TO_CLIENT 1

	/* Tracks the state for the outermost part of the stream */
	enum { EXPECTING_NEXT_RECORD,
		READING_TLS_RECORD_HEADER,
		READING_SSL_RECORD_HEADER,
		READING_SSL_PADDED_RECORD_HEADER,
		READING_ENCRYPTED_RECORD,
		READING_CLEAR_RECORD
	} tls_processing_state[2];

	/* Record header, enough for a TLS header */
	uint8_t record_header[2][5];

	/* How much of the record header have we read? */
	uint8_t record_header_read[2];

	/* The type of the tls record we are processing */
	uint8_t record_type[2];

	/* The length of the TLS record we are processing */
	uint16_t record_length[2];

	/* The length remaining to be read */
	uint16_t record_length_remaining[2];

	/* Rolling count of bytes seen which don't have (1 << 7) 
	 * set. 
	 */
	uint16_t low_bytes_sequence_length[2];

	/* If a heartbeat request was sent on one side of a
	 * a connection then a response of the same length
	 * is expected on the other side.
	 */
	uint16_t heartbeat_response_length_pending[2];
};

struct tls_parser_config {
	/* What is the maximum number of low-order bytes we can tolerate */
	uint16_t max_low_bytes_sequence_length;
};

/*
 * Parse an SSL/TLS record stream
 *
 * Parameters:
 *  tls_state           tracks the TLS/SSL state machine
 *  tls_parser_config   configuration paramaeters
 *  direction           either CLIENT_TO_SERVER, or SERVER_TO_CLIENT
 *  data_ptr            pointer to the data stream to parse
 *  data_len            how much data is there to parse
 *  message             if we encounter an error, will be updated to point to
 *                      an error message
 *
 * Return:
 *     0   No problem encountered
 *    -1   A problem was encountered handling the record stream 
 */
extern int tls_ssl2_record_parser(struct tls_state *tls_state, struct tls_parser_config *config,
				  int direction, const uint8_t * data_ptr, uint32_t data_len, char **message);
