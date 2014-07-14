# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#

nf_conntrack_tls-objs := nf_conntrack_tls_core.o tls_ssl_record_parser.o
obj-m := nf_conntrack_tls.o

# This module is experimental, hence the DEBUG
CFLAGS_nf_conntrack_tls_core.o := -DDEBUG
CFLAGS_tls_ssl_record_parser.o := -DDEBUG
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
