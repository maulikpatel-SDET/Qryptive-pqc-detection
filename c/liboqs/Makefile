# Build with: make   (needs liboqs installed: https://github.com/open-quantum-safe/liboqs)
CFLAGS = -Wall -O2
LDLIBS = -loqs -lcrypto
all: liboqs_mlkem liboqs_mldsa liboqs_falcon liboqs_sphincs
clean:
	rm -f liboqs_mlkem liboqs_mldsa liboqs_falcon liboqs_sphincs
