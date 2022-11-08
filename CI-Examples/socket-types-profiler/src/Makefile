ARCH_LIBDIR := /lib/$(shell $(CC) -dumpmachine)
REPO_ROOT := $(shell git rev-parse --show-toplevel)
LIBXDP_H := $(REPO_ROOT)/subprojects/xdp-tools-1.2.3/headers
LIBXDP_L := $(REPO_ROOT)/subprojects/xdp-tools-1.2.3/lib/libxdp/libxdp.a
LIBBPF_L := $(REPO_ROOT)/subprojects/xdp-tools-1.2.3/lib/libbpf/src/libbpf.a
LIBBPF_H := $(REPO_ROOT)/subprojects/xdp-tools-1.2.3/lib/libbpf/src/root/usr/include

CC=clang
CFLAGS=-O3 -std=gnu11
LDFLAGS=-L$(dir $(LIBXDP_L)) -L$(dir $(LIBBPF_L))
LDLIBS=-l:libxdp.a -l:libbpf.a -lz -lelf
INC=-I$(LIBXDP_H) -I$(LIBBPF_H)
LOG_LEVEL=error

COMMON_FILES=perf-common perf-xdp-common
COMMON_SRC=$(COMMON_FILES:=.c)
COMMON_HDR=$(COMMON_FILES:=.h)

SERVER_FILES=perf-server perf-inet-server perf-unix-server perf-xdp-server
SERVER_SRC=$(SERVER_FILES:=.c)
SERVER_HDR=$(SERVER_FILES:=.h)

CLIENT_FILES=perf-client perf-inet-client perf-unix-client perf-xdp-client
CLIENT_SRC=$(CLIENT_FILES:=.c)
CLIENT_HDR=$(CLIENT_FILES:=.h)

MANIFEST_TARGETS=perf-server.manifest perf-client.manifest
ifeq ($(SGX),1)
MANIFEST_TARGETS=perf-server.manifest.sgx perf-client.manifest.sgx \
	perf-server.token perf-client.token \
	perf-server.sig perf-client.sig
endif

all: check_libs perf-xdp-loader perf-server perf-client $(MANIFEST_TARGETS)

.PHONY: clean

clean:
	rm -rf perf-xdp-loader perf-server perf-client \
		*.manifest *.manifest.sgx *.sig *.token

check_libs:
	@( test -d "$(LIBXDP_H)" && test -s "$(LIBXDP_L)" && test -s "$(LIBBPF_L)" ) \
		|| ( echo "\n[!] Make sure is Gramine is built first with -Dxdp=enabled\n" && exit 1 )

perf-xdp-loader:
	$(CC) $(CFLAGS) $(LDFLAGS) $(INC) $@.c -o $@ $(LDLIBS)

perf-server: $(SERVER_SRC) $(SERVER_HDR) $(COMMON_SRC) $(COMMON_HDR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(INC) $(SERVER_SRC) $(COMMON_SRC) -o $@ $(LDLIBS)

perf-server.manifest: perf.manifest.template
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Dperf_prog=perf-server \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< $@

perf-server.sig perf-server.manifest.sgx: perf-server_sgx_sign
	@:

.INTERMEDIATE: perf-server_sgx_sign
perf-server_sgx_sign: perf-server.manifest perf-server
	gramine-sgx-sign --manifest $< --output $<.sgx

perf-server.token: perf-server.sig
	gramine-sgx-get-token --output $@ --sig $<

perf-client: $(CLIENT_SRC) $(CLIENT_HDR) $(COMMON_SRC) $(COMMON_HDR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(INC) $(CLIENT_SRC) $(COMMON_SRC) -o $@ $(LDLIBS)

perf-client.manifest: perf.manifest.template
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Dperf_prog=perf-client \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< $@

perf-client.sig perf-client.manifest.sgx: perf-client_sgx_sign
	@:

.INTERMEDIATE: perf-client_sgx_sign
perf-client_sgx_sign: perf-client.manifest perf-client
	gramine-sgx-sign --manifest $< --output $<.sgx

perf-client.token: perf-client.sig
	gramine-sgx-get-token --output $@ --sig $<
