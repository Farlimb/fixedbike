# # BIKE reference and optimized implementations assume that OpenSSL and NTL libraries are available in the platform.

# # To compile this code for NIST KAT routine use: make bike-nist-kat
# # To compile this code for demo tests use: make bike-demo-test
# # To compile client and server use: make bike-client-server

# # TO EDIT PARAMETERS AND SELECT THE BIKE VARIANT: please edit defs.h file in the indicated sections.

# # The file measurements.h controls how the cycles are counted. Note that #define REPEAT is initially set to 100,
# # which means that every keygen, encaps and decaps is repeated 100 times and the number of cycles is averaged.

# # Verbose levels: 0, 1, 2 or 3
# VERBOSE=0

# CC:=C:/msys64/mingw64/bin/g++.exe
# CFLAGS:=-m64 -O0 -g -march=native -funroll-loops -ffast-math -lole32 -loleaut32 -lwbemuuid#-i

# SRC:=*.c ntl.cpp FromNIST/rng.c FromNIST/aes.c
# INCLUDE:=-I. -I$(OpenSSL)/include -L$(OpenSSL)/lib -std=c++11 -lcrypto -lssl -lm -lgmp -lpthread -lws2_32

# all: bike-nist-kat bike-client bike-server bike-demo-test

# bike-demo-test: $(SRC) *.h tests/test.c
# 	$(CC) $(CFLAGS) tests/test.c $(SRC) $(INCLUDE) -DVERBOSE=$(VERBOSE) -DNIST_RAND=1 -lole32 -loleaut32 -lwbemuuid -o $@

# bike-nist-kat: $(SRC) *.h FromNIST/*.h FromNIST/PQCgenKAT_kem.c
# 	$(CC) $(CFLAGS) FromNIST/PQCgenKAT_kem.c $(SRC) $(INCLUDE) -DVERBOSE=$(VERBOSE) -DNIST_RAND=1 -lole32 -loleaut32 -lwbemuuid -o $@

# bike-client: $(SRC) *.h tests/client.c
# 	$(CC) $(CFLAGS) tests/client.c $(SRC) $(INCLUDE) -DVERBOSE=$(VERBOSE) -DNIST_RAND=1 -lole32 -loleaut32 -lwbemuuid -o $@

# bike-server: $(SRC) *.h tests/server.c
# 	$(CC) $(CFLAGS) tests/server.c $(SRC) $(INCLUDE) -DVERBOSE=$(VERBOSE) -DNIST_RAND=1 -lole32 -loleaut32 -lwbemuuid -o $@

# bike-client-server: bike-client bike-server
# 	@echo "Built bike-client and bike-server"

# clean:
# 	rm -f PQCkemKAT_*
# 	rm -f bike*

#above is old makefile
VERBOSE=0

CC=g++
CFLAGS=-m64 -O0 -g -march=native -funroll-loops -ffast-math

SRC=*.c ntl.cpp FromNIST/rng.c FromNIST/aes.c
INCLUDE=-I. -std=c++11 -lcrypto -lssl -lm -lgmp -lpthread -lntl

all: bike-nist-kat bike-client bike-server bike-demo-test implementation-check

bike-demo-test: $(SRC) *.h tests/test.c
	$(CC) $(CFLAGS) tests/test.c $(SRC) $(INCLUDE) -DVERBOSE=$(VERBOSE) -DNIST_RAND=1 -o $@

implementation-check: $(SRC) *.h tests/implementationcheck.c
	$(CC) $(CFLAGS) tests/implementationcheck.c $(SRC) $(INCLUDE) -DVERBOSE=$(VERBOSE) -DNIST_RAND=1 -o $@

bike-nist-kat: $(SRC) *.h FromNIST/*.h FromNIST/PQCgenKAT_kem.c
	$(CC) $(CFLAGS) FromNIST/PQCgenKAT_kem.c $(SRC) $(INCLUDE) -DVERBOSE=$(VERBOSE) -DNIST_RAND=1 -o $@

bike-client: $(SRC) *.h tests/client.c
	$(CC) $(CFLAGS) tests/client.c $(SRC) $(INCLUDE) -DVERBOSE=$(VERBOSE) -DNIST_RAND=1 -o $@

bike-server: $(SRC) *.h tests/server.c
	$(CC) $(CFLAGS) tests/server.c $(SRC) $(INCLUDE) -DVERBOSE=$(VERBOSE) -DNIST_RAND=1 -o $@

bike-client-server: bike-client bike-server
	@echo "Built bike-client and bike-server"

clean:
	rm -f PQCkemKAT_*
	rm -f bike*