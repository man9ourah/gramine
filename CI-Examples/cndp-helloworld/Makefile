ARCH_LIBDIR := /lib/$(shell $(CC) -dumpmachine)
LOG_LEVEL=error

MANIFEST_TARGETS=helloworld.manifest
ifeq ($(SGX),1)
MANIFEST_TARGETS=helloworld.manifest.sgx helloworld.token helloworld.sig
endif

all: $(MANIFEST_TARGETS)

.PHONY: clean

clean:
	rm -rf *.manifest *.manifest.sgx *.sig *.token

helloworld.manifest: helloworld.manifest.template
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< $@

helloworld.sig helloworld.manifest.sgx: helloworld_sgx_sign
	@:

.INTERMEDIATE: helloworld_sgx_sign
helloworld_sgx_sign: helloworld.manifest helloworld
	gramine-sgx-sign --manifest $< --output $<.sgx

helloworld.token: helloworld.sig
	gramine-sgx-get-token --output $@ --sig $<
