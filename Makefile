CC = gcc
CFLAGS = -Wall -O2

all: coretaskd server decryptor

coretaskd: main.c
	$(CC) $(CFLAGS) main.c -o coretaskd -ludev -lcrypto -lssl -lpcap -lX11

server: server.c
	$(CC) $(CFLAGS) server.c -o server -lssl -lcrypto -lnet

decryptor: screenshot-decryptor.c
	$(CC) $(CFLAGS) screenshot-decryptor.c -o screenshot-decryptor

clean:
	rm -f coretaskd server screenshot-decryptor
