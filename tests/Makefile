GTEST_DIR=../googletest
CXXFLAGS=-O3 -Wall -I../include/ -I../src/ -I$(GTEST_DIR) -I$(GTEST_DIR)/include
CXX=clang
CC=clang
LDFLAGS=-L../_build -L_build/
CFLAGS=$(CXXFLAGS)

all: run_tests 

run_tests: tests.done

rerun_tests:
	(rm tests.done; make run_tests)

build_tests: crypto_test archive_test bigint_test x509_test tls_test asn1_test

tests.done: build_tests ../_build/libmintls.a
	(cd test_vectors; make)
	@/usr/bin/env echo "[*] Running tls unit tests.... "
	@./tls_test --quiet
	@/usr/bin/env echo "[*] Running X.509 unit tests.... "
	@./x509_test --quiet
	@/usr/bin/env echo "[*] Running X.509 regressions.... "
	@bash ./x509_regressions.sh
	@/usr/bin/env echo "[*] Running X.509 path validation tests.... "
	@bash ./x509_path_tests.sh
	@/usr/bin/env echo "[*] Running archive unit tests.... "
	@./archive_test --quiet
	@/usr/bin/env echo "[*] Running ASN.1 unit tests.... "
	@./asn1_test --quiet
	@/usr/bin/env echo "[*] Running crypto unit tests.... "
	@./crypto_test --quiet
#	@/usr/bin/env echo "[*] Running BigInt unit tests.... "
#	@./bigint_test --quiet
	@/usr/bin/env echo > tests.done

####
#
# Google Test stuff
#
_build/gtest-all.o:
	$(CXX) $(CXXFLAGS) -c $(GTEST_DIR)/src/gtest-all.cc -o $@ 

_build/gtest_main.o:
	$(CXX) $(CXXFLAGS) -c $(GTEST_DIR)/src/gtest_main.cc -o $@ 

_build/libgtest.a: _build/gtest-all.o
	ar -rv $@ $<

_build/libgtest-main.a: _build/gtest_main.o
	ar -rv $@ $<

####
#
# The tests
#
_build/%.o: %.cpp
	@mkdir -p _build
	$(CXX) ${CXXFLAGS} -std=c++0x -c `pwd`/$< -o $@ 

_build/%.o: %.c
	@mkdir -p _build
	$(CC) ${CFLAGS} -c `pwd`/$< -o $@ 

tls_test:_build/tls_key_expansion.o _build/tls_prf_test.o _build/tls_handshake_test.o _build/tls_serialization_test.o _build/tls_record_test.o ../_build/libmintls.a _build/libgtest.a
	$(CXX) $^ -o $@ -lstdc++ -lgtest -lmintls $(LDFLAGS) 

x509_test:_build/x509_test.o ../_build/libmintls.a
	$(CXX) $^ -o $@ -lstdc++ -lgtest -lmintls $(LDFLAGS) 

crypto_test: _build/sha_test.o _build/aes_test.o _build/hmac_test.o _build/rsa_test.o _build/ecdh_nist_test.o ../_build/libmintls.a _build/libgtest.a
	$(CXX) $^ -o $@ -lstdc++ -lgtest -lmintls $(LDFLAGS) 

archive_test: _build/archive_test.o ../_build/libmintls.a _build/libgtest.a
	$(CXX) $^ -o $@ -lstdc++ -lgtest -lmintls $(LDFLAGS) 

bigint_test: _build/bigint_test.o ../_build/libmintls.a _build/libgtest.a
	$(CC) $^ -o $@ -lstdc++ -lgtest -lmintls $(LDFLAGS)

asn1_test: _build/asn1_test.o ../_build/libmintls.a _build/libgtest.a
	$(CXX) $^ -o $@ -lstdc++ -lgtest -lmintls $(LDFLAGS) 

speed_test: aes_test
	@./aes_test aesspeedtest

clean:
	rm -rf KAT_AES _build aes_test tls_test x509_test crypto_test archive_test bigint_test asn1_test ghash_test

# vim: set noexpandtab
