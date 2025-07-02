# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

BUILDDIR = build
OPENSSL_MODULES_DIR ?= /lib/x86_64-linux-gnu/ossl-modules/
CLIENT_DIR ?= $(shell pwd)/demo/client
SERVER_DIR ?= $(shell pwd)/demo/server
CA_DIR ?= $(shell pwd)/demo/CA
SERIALIZED_DATA_DIR ?= $(CLIENT_DIR)/serialized_data
INTEGRATION_TEST_DIR= ./tests/integration

# Enable EC: -DEC_ON
# Enable Dilithium: -DDILITHIUM_ON
# Enable log all byte array: -DLOG_BYTE_ARRARY_ON
# Enable log all base 64 string: -DLOG_B64_ON
# Enable log all base 64 string: -DLOG_FOR_CYCLE_ON
CFLAGS = -Wall -g -DEC_ON -DLOG_LEVEL=0 -DLOG_B64_ON -DSERIALIZATION_FOLDER="\""$(SERIALIZED_DATA_DIR)"\""

# GTA SW Provider - merged static lib
LDFLAGS = -Wall -g -L./deps/gta_api/lib_latest

LIBSRCS = $(wildcard provider/*.c provider/stream/*.c provider/logger/*.c provider/algorithms/*.c provider/algorithms/dilithium/*.c provider/algorithms/ecdsa/*.c )
LIBOBJS = $(addprefix $(BUILDDIR)/,$(patsubst %.c,%.o,$(LIBSRCS)))

.PHONY: all
all: $(BUILDDIR)/gta.so

$(BUILDDIR)/gta.so: $(LIBOBJS)
	$(CC) -shared -o $@ $(LDFLAGS) $^ -lgta_sw_provider_merged -lgta -lm

$(BUILDDIR)/%.o: %.c
	mkdir -p $(@D)
	$(CC) -c $(CFLAGS) -fpic -o $@ -c $<

.PHONY: clean
clean:
	rm -rf $(BUILDDIR)
	
.PHONY: install
install: $(BUILDDIR)/gta.so
	cp $(BUILDDIR)/gta.so $(OPENSSL_MODULES_DIR)

.PHONY: remove
remove:
	rm -rf $(CA_DIR)
	rm -rf $(SERIALIZED_DATA_DIR)
	rm -f $(CLIENT_DIR)/*.pem
	rm -f $(SERVER_DIR)/*.pem
	rm -f $(INTEGRATION_TEST_DIR)/tools/bash_test_tools

$(INTEGRATION_TEST_DIR)/tools/bash_test_tools:
	wget -P $(INTEGRATION_TEST_DIR)/tools/ https://raw.githubusercontent.com/thorsteinssonh/bash_test_tools/master/bash_test_tools

.PHONY: test
test: $(INTEGRATION_TEST_DIR)/tools/bash_test_tools
	(cd $(INTEGRATION_TEST_DIR) && ./run_tests.sh)

.PHONY: uninstall
uninstall:
	rm -f $(OPENSSL_MODULES_DIR)/gta.so
