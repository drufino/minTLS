all: aes_tables.native aes_test.native ghash.native

ghash.native: ghash.ml GF2n.ml
	/usr/local/bin/ocamlbuild -cflags -g,-bin-annot ghash.native

aes_test.native: aes_test.ml aes.ml GF2n.ml GF2n.mli
	/usr/local/bin/ocamlbuild -cflags -bin-annot aes_test.native aes_tables.native

aes_tables.native: aes.ml aes_tables.ml GF2n.ml GF2n.mli
	/usr/local/bin/ocamlbuild -cflags -bin-annot aes_tables.native aes_test.native

clean:
	ocamlbuild -clean
