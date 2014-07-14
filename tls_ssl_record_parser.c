/* Read this header for a description of the state machine */
#include "tls_ssl_record_parser.h"

/* Access a member of the state structure, either for the direction we're
 * handling, or for the other (peer) direction.
 */
#define STATE_MEMBER( member )  tls_state->member[direction]
#define PEER_STATE_MEMBER( member )  tls_state->member[!direction]

/* Update the state machine
 */
#define STATE_UPDATE( state )   tls_state->tls_processing_state[direction] = (state)

/* Consume a byte from the data stream
 */
#define CONSUME_BYTES( len )    data_ptr += (len); data_len -= (len);
#define CONSUME_BYTE()          CONSUME_BYTES( 1 )

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
int tls_ssl2_record_parser(struct tls_state *tls_state, struct tls_parser_config *tls_parser_config,
			   int direction, const uint8_t * data_ptr, uint32_t data_len, char **message)
{
	while (data_len) {
		int i, amount_to_read;

		switch (tls_state->tls_processing_state[direction]) {

		case EXPECTING_NEXT_RECORD:
			/* Reset the header */
			STATE_MEMBER(record_header_read) = 0;

			/* We now have the first byte of a new record, but we need to figure out
			 * if it's an SSL2 or TLS record. If either of the first two bits are set,
			 * then it's SSL2. Otherwise we'll treat it as TLS.
			 */
			if (*data_ptr & 0x80) {
				STATE_UPDATE(READING_SSL_RECORD_HEADER);
				continue;
			} else if (*data_ptr & 0x40) {
				STATE_UPDATE(READING_SSL_PADDED_RECORD_HEADER);
				continue;
			} else if (*data_ptr < MINIMUM_TLS_CONTENT_TYPE || *data_ptr > MAXIMUM_TLS_CONTENT_TYPE) {
				*message = "invalid record type encountered";
				return -1;
			}

			/* This is a TLS record */
			STATE_UPDATE(READING_TLS_RECORD_HEADER);
			continue;

		case READING_SSL_RECORD_HEADER:
			STATE_MEMBER(record_header)[STATE_MEMBER(record_header_read)] = *data_ptr;
			STATE_MEMBER(record_header_read) += 1;
			CONSUME_BYTE();

			/* Two byte length, plus the record type */
			if (3 > STATE_MEMBER(record_header_read)) {
				continue;
			}

			STATE_MEMBER(record_length) =
			    ((STATE_MEMBER(record_header)[0] & 0x7f) << 8) | STATE_MEMBER(record_header)[1];

			/* One byte is consumed already (the record type) */
			STATE_MEMBER(record_length_remaining) = STATE_MEMBER(record_length) - 1;
			STATE_MEMBER(record_type) = STATE_MEMBER(record_header)[2];

			if (0 == STATE_MEMBER(record_length)) {
				*message = "0 length SSL record detected";
				return -1;
			}

			switch (STATE_MEMBER(record_type)) {
			case SSL_CLIENT_HELLO:
				if (direction != CLIENT_TO_SERVER) {
					*message = "Client Hello in wrong direction";
					return -1;
				}
				STATE_UPDATE(READING_CLEAR_RECORD);
				break;
			case SSL_SERVER_HELLO:
				if (direction != SERVER_TO_CLIENT) {
					*message = "Server Hello in wrong direction";
					return -1;
				}
				STATE_UPDATE(READING_CLEAR_RECORD);
				break;
			case SSL_CLIENT_MASTER_KEY:
				if (direction != CLIENT_TO_SERVER) {
					*message = "Client master key in wrong direction";
					return -1;
				}
				STATE_UPDATE(READING_CLEAR_RECORD);
				break;
			default:
				STATE_UPDATE(READING_ENCRYPTED_RECORD);
				break;
			}

			continue;

		case READING_SSL_PADDED_RECORD_HEADER:
			STATE_MEMBER(record_header)[STATE_MEMBER(record_header_read)] = *data_ptr;
			STATE_MEMBER(record_header_read) += 1;
			CONSUME_BYTE();

			/* Three byte length, plus the message type */
			if (4 > STATE_MEMBER(record_header_read)) {
				continue;
			}

			STATE_MEMBER(record_length) =
			    ((STATE_MEMBER(record_header)[0] & 0x3f) << 8) | STATE_MEMBER(record_header)[1];

			/* Add the padding length to the record length */
			STATE_MEMBER(record_length) += STATE_MEMBER(record_header)[2];

			/* One byte is consumed already (the record type) */
			STATE_MEMBER(record_length_remaining) = STATE_MEMBER(record_length) - 1;
			STATE_MEMBER(record_type) = STATE_MEMBER(record_header)[3];

			if (0 == STATE_MEMBER(record_length)) {
				*message = "0 length SSL record detected";
				return -1;
			}

			STATE_UPDATE(READING_ENCRYPTED_RECORD);

			continue;

		case READING_TLS_RECORD_HEADER:
			STATE_MEMBER(record_header)[STATE_MEMBER(record_header_read)] = *data_ptr;
			STATE_MEMBER(record_header_read) += 1;
			CONSUME_BYTE();

			/* One byte record type, 2 byte version code, 2 byte length code */
			if (5 > STATE_MEMBER(record_header_read)) {
				continue;
			}

			STATE_MEMBER(record_length) =
			    STATE_MEMBER(record_header)[3] << 8 | STATE_MEMBER(record_header)[4];
			STATE_MEMBER(record_length_remaining) = STATE_MEMBER(record_length);
			STATE_MEMBER(record_type) = STATE_MEMBER(record_header)[0];

			switch (STATE_MEMBER(record_type)) {
			case HEARTBEAT_TLS_CONTENT_TYPE:
				/* Check for a minimum length */
				if (HEARTBEAT_TLS_MINIMUM_SIZE > STATE_MEMBER(record_length)) {
					*message = "Invalid (too short) Heartbeat message detected";
					return -1;
				}

				/* Check if a heartbeat response was pending */
				if (STATE_MEMBER(heartbeat_response_length_pending)) {

					/* If so, do the lengths match? */
					if (STATE_MEMBER(record_length) !=
					    STATE_MEMBER(heartbeat_response_length_pending)) {
						*message = "Heartbleed response detected";
						return -1;
					}

					/* Reset */
					STATE_MEMBER(heartbeat_response_length_pending) = 0;
				} else {
					/* No response was pending, this is a request. Set
					 * a response pending on the peer state.
					 */
					PEER_STATE_MEMBER(heartbeat_response_length_pending) =
					    STATE_MEMBER(record_length);;
				}

				/* Fall through */
			case HANDSHAKE_TLS_CONTENT_TYPE:
				STATE_UPDATE(READING_CLEAR_RECORD);
				break;

			default:
				STATE_UPDATE(READING_ENCRYPTED_RECORD);
				break;
			}

			continue;

		case READING_ENCRYPTED_RECORD:
			if (!tls_parser_config->max_low_bytes_sequence_length) {
				STATE_UPDATE(READING_CLEAR_RECORD);
				continue;
			}

			amount_to_read = STATE_MEMBER(record_length_remaining);
			if (amount_to_read > data_len) {
				amount_to_read = data_len;
			}

			/* Perform our simple run-length test */
			for (i = 0; i < amount_to_read; i++) {
				if (data_ptr[i] & (1 << 7)) {
					STATE_MEMBER(low_bytes_sequence_length) = 0;
				} else {
					STATE_MEMBER(low_bytes_sequence_length)++;

					if (STATE_MEMBER(low_bytes_sequence_length) >
					    tls_parser_config->max_low_bytes_sequence_length) {
						*message = "Data smuggling detected";
						return -1;
					}
				}
			}

			/* Fall through ... */

		case READING_CLEAR_RECORD:
			amount_to_read = STATE_MEMBER(record_length_remaining);
			if (amount_to_read > data_len) {
				amount_to_read = data_len;
			}

			STATE_MEMBER(record_length_remaining) -= amount_to_read;
			CONSUME_BYTES(amount_to_read);

			/* If we reached the end, look for the next record */
			if (0 == STATE_MEMBER(record_length_remaining)) {
				STATE_UPDATE(EXPECTING_NEXT_RECORD);
			}

			continue;

		default:
			*message = "Invalid record parsing state reached";
			return -1;
		}
	}

	return 0;
}
