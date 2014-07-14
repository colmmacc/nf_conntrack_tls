/*
 *     XXXXXXXXX THIS MODULE IS AN EXPERIMENTAL WORK IN PROGRESS  XXXXXXXXX 
 *
 * The ultimate goal of this module is to provide a framework for safeguarding an 
 * SSL/TLS stack. This module tracks the SSL/TLS state machine and drops connections 
 * that no longer appear to obey some semantics of the SSL/TLS protocols. 
 *
 * For now, it provides three protocol-level validations:
 *
 *  1.  This module understands TLS heartbeats and can detect and stop
 *      a heartbleed attempt.
 *
 *  2.  All-non-handshake and heartbeat records are subject to an optional
 *      "suspicious sequence length" check. This check places a limit on how
 *      many bytes without their first bit set (ie byte value is < 128) can
 *      appear in a contiguous sequence. An encrypted connection should consist
 *      of random-looking data, a long sequence of zeroed bytes or ascii
 *      data may indicate that something nefarious is going on. The default
 *      length limit is 128 bytes, however this can be changed at module load time.
 *
 * 3.   Directionality is enforced on SSL2 handshake messages.
 *
 * Further validations are possible, including: TLS handshake directionality,
 * protocol version tracking, protocol downgrade mitigation. These and more
 * are future work. Contributions are welcome!
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/slab.h>
#include <linux/ipv6.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <net/checksum.h>
#include <net/tcp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>

#include "tls_ssl_record_parser.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Colm MacCárthaigh <colmmacc@amazon.com>");
MODULE_DESCRIPTION("TLS connection tracker");
MODULE_ALIAS("ip_conntrack_tls");
MODULE_ALIAS_NFCT_HELPER("tls");

#define HTTPS_PORT          443	/* Default port */
#define SUSPICIOUS_LENGTH   128	/* Default max length of suspicious sequence permitted */

/* How long should this state be maintained ? */
static const struct nf_conntrack_expect_policy tls_exp_policy = {
	.max_expected = 1,
	.timeout = 5 * 60,
	.name = "tls",
};

#define MAX_PORTS 8
static u_int16_t ports[MAX_PORTS];
static unsigned int ports_c;
module_param_array(ports, ushort, &ports_c, 0400);

/* We support a log only mode */
static bool log_only_mode;
module_param(log_only_mode, bool, 0600);

/* The maximum length of a suspicious sequence is tunable */
static unsigned int suspicious_sequence_length = SUSPICIOUS_LENGTH;
module_param(suspicious_sequence_length, uint, 0400);

/* We allocate a buffer per CPU */
static char *packet_buffer;

/* Stores the parser config, which is global */
static struct tls_parser_config tls_parser_config;

/* How big each buffer is. 16k should cover jumboframes */
#define PACKET_BUFFER_LEN 16384

static int tls_helper(struct sk_buff *skb, unsigned int protoff, struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	unsigned int data_offset, tls_packet_len;
	int direction = CTINFO2DIR(ctinfo);
	int ret;
	struct tls_state *tls_state = nfct_help_data(ct);
	uint8_t *tls_packet;
	struct tcphdr tcp_header_data;
	struct tcphdr *tcp_header;
	char *message;

	if (NULL == tls_state) {
		return NF_DROP;
	}

	if (sizeof(struct tcphdr) >= skb->len) {
		return NF_DROP;
	}

	tcp_header = skb_header_pointer(skb, protoff, sizeof(tcp_header_data), &tcp_header_data);
	if (NULL == tcp_header)
		return NF_DROP;

	data_offset = protoff + (tcp_header->doff * 4);
	if (data_offset > skb->len) {
		return NF_DROP;
	}
	/* Accept empty TCP messages (handhakes and keepalives) */
	else if (data_offset == skb->len) {
		return NF_ACCEPT;
	}

	tls_packet_len = skb->len - data_offset;
	do {
		int parser_return;
		int amount_to_read;

		amount_to_read = tls_packet_len;
		if (amount_to_read > PACKET_BUFFER_LEN) {
			amount_to_read = PACKET_BUFFER_LEN;
		}

		/* Default is to accept the packet */
		ret = NF_ACCEPT;

		/* Aquire the lock and linearize the skb if neccessary */
		tls_packet = skb_header_pointer(skb, data_offset, amount_to_read, &get_cpu_var(packet_buffer));
		if (NULL == tls_packet) {
			return NF_DROP;
		}

		/* O.k, at this point we have tls_packet, which points to the actual
		 * TLS wire-level data, in the TCP packet payload section.
		 */
		message = NULL;
		parser_return =
		    tls_ssl2_record_parser(tls_state, &tls_parser_config, direction, tls_packet, tls_packet_len,
					   &message);
		if (parser_return) {
			ret = NF_DROP;
			break;
		}

		tls_packet_len -= amount_to_read;
		data_offset += amount_to_read;
	} while (tls_packet_len);

	if (message) {
		pr_debug("nf_conntrack_tls: dropping packet due to '%s'", message);
		nf_ct_helper_log(skb, ct, "nf_conntrack_tls: dropping packet due to '%s'", message);
	} else if (NF_DROP == ret) {
		pr_debug("nf_conntrack_tls: dropping packet");
		nf_ct_helper_log(skb, ct, "nf_conntrack_tls: dropping packet");
	}

	if (log_only_mode) {
		ret = NF_ACCEPT;
	}

	return ret;
}

static struct nf_conntrack_helper tls_helpers[MAX_PORTS][2] __read_mostly;

static void nf_conntrack_tls_fini(void)
{
	int i, j;
	for (i = 0; i < ports_c; i++) {
		for (j = 0; j < 2; j++) {
			if (NULL == tls_helpers[i][j].me)
				continue;

			pr_debug("nf_ct_tls: unregistering helper for pf: %d "
				 "port: %d\n", tls_helpers[i][j].tuple.src.l3num, ports[i]);
			nf_conntrack_helper_unregister(&tls_helpers[i][j]);
		}
	}
}

static int __init nf_conntrack_tls_init(void)
{
	int i, j = -1, ret = 0;

	/* Allocate a 16k buffer per CPU for linearizing the SKB */
	packet_buffer = (char *)alloc_percpu(char[PACKET_BUFFER_LEN]);
	if (!packet_buffer)
		return -ENOMEM;

	/* Set the config */
	tls_parser_config.max_low_bytes_sequence_length = suspicious_sequence_length;

	/* If given no arguments, then run on port 443 */
	if (0 == ports_c)
		ports[ports_c++] = HTTPS_PORT;

	/* Register an IPv4 and IPv6 helper for each port */
	for (i = 0; i < ports_c; i++) {
		tls_helpers[i][0].tuple.src.l3num = PF_INET;
		tls_helpers[i][1].tuple.src.l3num = PF_INET6;
		for (j = 0; j < 2; j++) {
			/* We have two tls states, one for client, one for server */
			tls_helpers[i][j].data_len = sizeof(struct tls_state);
			tls_helpers[i][j].tuple.src.u.tcp.port = htons(ports[i]);
			tls_helpers[i][j].tuple.dst.protonum = IPPROTO_TCP;
			tls_helpers[i][j].expect_policy = &tls_exp_policy;
			tls_helpers[i][j].me = THIS_MODULE;
			tls_helpers[i][j].help = tls_helper;

			sprintf(tls_helpers[i][j].name, "tls-%d", ports[i]);
			pr_debug("nf_ct_tls: registering helper for pf: %d "
				 "port: %d\n", tls_helpers[i][j].tuple.src.l3num, ports[i]);

			ret = nf_conntrack_helper_register(&tls_helpers[i][j]);
			if (ret) {
				printk(KERN_ERR "nf_ct_tls: failed to register"
				       " helper for pf: %d port: %d\n", tls_helpers[i][j].tuple.src.l3num, ports[i]);
				tls_helpers[i][j].me = NULL;
				nf_conntrack_tls_fini();
				return ret;
			}
		}
	}

	return 0;
}

module_init(nf_conntrack_tls_init);
module_exit(nf_conntrack_tls_fini);
