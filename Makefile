CC=g++
CFLAGS=-Wall -g -O3 -std=c++11 `pkg-config --cflags openssl`
LDFLAGS=
LDLIBS=`pkg-config --libs openssl`

SERVER=server.o encrypt.o
CLIENT=client.o encrypt.o

all: server client

server: $(SERVER)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

client: $(CLIENT)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean
clean:
	-rm server client *.o
