all: tests

tests: KAS_ECC KAT_SHA KAT_RSA KAT_AES KAT_HMAC X509tests

X509tests: nist_x509.tgz
	tar -zxf nist_x509.tgz

nist_x509.tgz:
	curl http://csrc.nist.gov/groups/ST/crypto_apps_infra/documents/x509tests.tgz > nist_x509.tgz

KAT_AES_MMT.zip:
	curl http://csrc.nist.gov/groups/STM/cavp/documents/aes/aesmmt.zip > KAT_AES_MMT.zip

KAT_AES.zip:
	curl http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip > KAT_AES.zip

KAT_RSA.zip:
	curl http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3rsatestvectors.zip > KAT_RSA.zip

KAT_AES: KAT_AES.zip KAT_AES_MMT.zip
	mkdir -p KAT_AES
	unzip -oqq KAT_AES.zip -d KAT_AES
	unzip -oqq KAT_AES_MMT.zip -d KAT_AES

KAS_ECC: KAS_ECC.zip
	mkdir -p KAS_ECC
	unzip -oqq KAS_ECC.zip -d KAS_ECC

KAS_ECC.zip:
	curl http://csrc.nist.gov/groups/STM/cavp/documents/components/ecccdhtestvectors.zip > KAS_ECC.zip

KAT_SHA.zip:
	curl http://csrc.nist.gov/groups/STM/cavp/documents/shs/shabytetestvectors.zip > KAT_SHA.zip

KAT_HMAC.zip:
	curl http://csrc.nist.gov/groups/STM/cavp/documents/mac/hmactestvectors.zip > KAT_HMAC.zip

KAT_SHA: KAT_SHA.zip
	mkdir -p KAT_SHA
	unzip -oqq KAT_SHA.zip -d KAT_SHA

KAT_RSA: KAT_RSA.zip
	mkdir -p KAT_RSA
	unzip -oqq KAT_RSA.zip -d KAT_RSA

KAT_HMAC: KAT_HMAC.zip
	mkdir -p KAT_HMAC
	unzip -oqq KAT_HMAC.zip -d KAT_HMAC

# vim: set noexpandtab
