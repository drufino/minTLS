CXXFLAGS=-O3 -Wall -I../include/ -I../src/ 
CXX=clang
CC=clang
LDFLAGS=-L../_build -L_build/
CFLAGS=$(CXXFLAGS)
TARGETS=mintls_cert mintls_client

all: $(TARGETS)

_build/%.o: %.cpp
	mkdir -p _build
	$(CXX) ${CXXFLAGS} -std=c++0x -c `pwd`/$< -o $@ 

_build/%.o: %.c
	mkdir -p _build
	$(CXX) ${CXXFLAGS} -c `pwd`/$< -o $@ 

mintls_cert: _build/mintls_cert.o ../_build/libmintls.a
	$(CXX) $^ -o $@ -lstdc++ -lmintls $(LDFLAGS)

mintls_client: _build/mintls_client.o ../_build/libmintls.a
	$(CXX) $^ -o $@ -lstdc++ -lmintls $(LDFLAGS)

clean:
	rm -rf _build $(TARGETS)
