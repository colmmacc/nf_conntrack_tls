# SSL/TLS netfilter module

## THIS MODULE IS AN EXPERIMENTAL WORK IN PROGRESS

nf_conntrack_tls is an experimental connection tracking module for linux which
tracks the SSL/TLS state associated with an encrypted connection. The ultimate
goal of this module is to provide a framework to safeguard SSL/TLS application 
stacks.

This module tracks the SSL/TLS state machine and drops connections that no 
longer appear to obey some semantics of the SSL/TLS protocols. 

Initially, three protocol validations are performed:

1.  This module understands TLS heartbeats and can detect and stop a heartbleed attempt.
1.  All-non-handshake and heartbeat records are subject to an optional "suspicious sequence length" check. This check places a limit on how many bytes without their first bit set (ie byte value is < 128) can appear in a contiguous sequence. An SSL connection should consist of random-looking data, a suspiciously long sequence of zeroed bytes or ascii data may indicate that something nefarious is going on. The default length limit is 128, however this can be changed at module load time.
1. Directionality is enforced on SSL2 handshake messages.

Further validations are possible, including: TLS handshake directionality, protocol version tracking, protocol downgrade mitigation. These and more are future work, and contributions are welcome.

## Testing

To compile this and test this netfilter module on Amazon Linux:

    make
    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED -m helper --helper tls -p TCP --dport 443 -j ACCEPT
    sudo modprobe nf_conntrack
    sudo insmod ./nf_conntrack_tls.ko

Note that the Makefile has DEBUG defined, which slows the operation of the module. 
