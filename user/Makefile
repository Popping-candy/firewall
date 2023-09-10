CC=g++
CFLAGS=-Wall

BIN_DIR=.

.PHONY: all clean

all: client

client.o: client.cpp
	$(CC) $(CFLAGS) -c $< -o $@

util.o: util.cpp
	$(CC) $(CFLAGS) -c $< -o $@

client: client.o util.o
	$(CC) $(CFLAGS) $< -o $(BIN_DIR)/$@
	rm -f clirnt.o util.o

clean:
	rm -f $(BIN_DIR)/client
