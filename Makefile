CC=g++
CPPFLAGS=-Wall -O3 -std=c++11 `pkg-config --cflags openssl`
LDFLAGS=
LDLIBS=`pkg-config --libs openssl`

all: server client

server: server.o encrypt.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

client: client.o encrypt.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean
clean:
	-rm server client *.o
