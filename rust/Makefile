# LatticeScope (Rust) — convenience targets

CARGO ?= cargo
CC    ?= cc

.PHONY: all build release test demo mock pqclean clean fmt

all: release

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test

# Run both modules against the bundled mock (build.rs compiles the mock; this
# target is here for a make-driven workflow / to rebuild the mock standalone).
demo: release
	$(CARGO) run --release -- demo

# Build the mock target on its own, e.g. for use with an external harness.
mock:
	$(CC) -O3 -fPIC -shared -o examples/libmock_pqc.so examples/mock_pqc.c
	@echo "built examples/libmock_pqc.so"

# Fetch (sparse, shallow) and build real PQClean targets for the real-target
# negative controls documented in README.md under "Validation on real
# targets": ML-KEM-768 (crypto_kem_dec/enc, poly_frombytes) and ML-DSA-65
# (crypto_sign_verify). Exact --symbol overrides are documented there too.
PQCLEAN_DIR := .pqclean-src
PQCLEAN_REPO := https://github.com/PQClean/PQClean.git

pqclean:
	if [ ! -d $(PQCLEAN_DIR) ]; then \
		git clone --depth 1 --filter=blob:none --sparse $(PQCLEAN_REPO) $(PQCLEAN_DIR) && \
		cd $(PQCLEAN_DIR) && git sparse-checkout set crypto_kem/ml-kem-768 crypto_sign/ml-dsa-65 common; \
	fi
	$(CC) -O3 -fPIC -shared -std=c99 \
		-I $(PQCLEAN_DIR)/common -I $(PQCLEAN_DIR)/crypto_kem/ml-kem-768/clean \
		$(PQCLEAN_DIR)/crypto_kem/ml-kem-768/clean/*.c \
		$(PQCLEAN_DIR)/common/fips202.c $(PQCLEAN_DIR)/common/randombytes.c \
		-o libmlkem768_pqclean.so
	$(CC) -O3 -fPIC -shared -std=c99 \
		-I $(PQCLEAN_DIR)/common -I $(PQCLEAN_DIR)/crypto_sign/ml-dsa-65/clean \
		$(PQCLEAN_DIR)/crypto_sign/ml-dsa-65/clean/*.c \
		$(PQCLEAN_DIR)/common/fips202.c $(PQCLEAN_DIR)/common/randombytes.c \
		-o libmldsa65_pqclean.so
	@echo "built libmlkem768_pqclean.so and libmldsa65_pqclean.so — see README.md 'Validation on real targets' for --symbol overrides"

fmt:
	$(CARGO) fmt

clean:
	$(CARGO) clean
	rm -f examples/libmock_pqc.so libmlkem768_pqclean.so libmldsa65_pqclean.so
	rm -rf $(PQCLEAN_DIR)