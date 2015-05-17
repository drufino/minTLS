CC=clang
CXX=clang
CFLAGS=-O3 -Wall -mssse3 -mno-sse4 -Iinclude/ -Isrc/ -Werror
CXXFLAGS=$(CFLAGS) -std=c++11

.PHONY: tables tools

all: build_tests tools run_tests

tarball:
	(cd ../; tar --exclude aes.sublime-project --exclude tests/aes_test --exclude tests/sbox_test --exclude aes.sublime-workspace --exclude tests/KAT_AES.zip --exclude _build --exclude tests/KAT_AES --exclude tests/_build --exclude tables/_build --exclude docs --exclude .svn --exclude .DS_Store -zcvf aes_algebra-`date +%Y%m%d`.tgz aes_algebra)

googletest:
	curl https://googletest.googlecode.com/files/gtest-1.7.0.zip > gtest-1.7.0.zip
	unzip -q gtest-1.7.0.zip
	mv gtest-1.7.0 googletest
	rm -f gtest-1.7.0.zip

build_tests: _build/libmintls.a googletest
	(cd tests; $(MAKE) build_tests)

run_tests: _build/libmintls.a googletest
	(cd tests; $(MAKE) run_tests)

tools: _build/libmintls.a
	(cd tools; $(MAKE) all)

tables:
	(cd tables; $(MAKE) all)

_build/%.o: src/asn1/%.cpp
	@mkdir -p _build
	$(CC) $(CXXFLAGS) -c $< -o $@ 

_build/%.o: src/core/%.cpp
	@mkdir -p _build
	$(CC) $(CXXFLAGS) -c $< -o $@ 

_build/%.o: src/tls/%.cpp
	@mkdir -p _build
	$(CC) $(CXXFLAGS) -c $< -o $@ 

_build/%.o: src/core/%.c
	@mkdir -p _build
	$(CC) $(CFLAGS) -c $< -o $@ 

_build/%.o: src/%.cpp
	@mkdir -p _build
	$(CC) $(CXXFLAGS) -c $< -o $@ 

_build/%.o: src/crypto/%.c
	@mkdir -p _build
	$(CC) $(CFLAGS) -Isrc/crypto -c $< -o $@ 

_build/%.o: src/crypto/%.cpp
	@mkdir -p _build
	$(CC) $(CXXFLAGS) -Isrc/crypto -c $< -o $@ 

OBJ_FILES= \
	_build/aes.o			\
	_build/aes_simple.o 	\
	_build/aes_ssse3.o 		\
	_build/base64.o 		\
	_build/cipher.o 		\
	_build/ecdh.o 			\
	_build/ecp_p224.o 		\
	_build/ecp_p256.o 		\
	_build/sse_helpers.o 	\
	_build/hmac.o 			\
	_build/sha.o 			\
	_build/sha1.o			\
	_build/sha2.o 			\
	_build/sha4.o 			\
	_build/rsa.o 			\
	_build/pubkey.o 		\
	_build/tf_cpuid.o 		\
	_build/random.o 		\
	_build/bignum.o 		\
	_build/bigint.o 		\
	_build/asn1.o 			\
	_build/asn1_objects.o 	\
	_build/asn1_oid_registry.o \
	_build/asn1_archive.o 	\
	_build/tls_api.o 		\
	_build/tf_debug.o		\
	_build/tls_handshake.o	\
	_build/tls_client.o 	\
	_build/tls_config.o 	\
	_build/tls_protocol.o 	\
	_build/tls_ecc.o 		\
	_build/tls_primitives.o \
	_build/tls_certificate.o \
	_build/tls_ciphersuites.o \
	_build/tls_extensions.o \
	_build/tls_state.o 	 \
	_build/tls_x509_v3.o \
	_build/archive.o \
	_build/utf8string.o

_build/libmintls.a: $(OBJ_FILES)
	ar -cr $@ $^

clean:
	(cd tables; $(MAKE) clean);
	(cd tests; $(MAKE) clean);
	(cd tools; $(MAKE) clean);
	rm -rf _build

# vim: set noexpandtab
