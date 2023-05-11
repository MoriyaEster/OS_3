CC=gcc
CFLAGS=-c
LDFLAGS=-lcrypto

all: stnc

stnc: stnc.o
	$(CC) $(LDFLAGS) stnc.o -o stnc

stnc.o: stnc.c
	$(CC) $(CFLAGS) stnc.c

clean:
	rm -f stnc stnc.o udp* 100MB.bin tcp* uds* pipe* mm*
