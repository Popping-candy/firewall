CC=g++
CFLAGS = -std=c++11

all: client

client: client.o util.o
	$(CC) $(CFLAGS) -o client client.o util.o
		rm -f *.o

client.o: client.cpp client.h
	$(CC) $(CFLAGS) -c client.cpp

util.o: util.cpp util.h
	$(CC) $(CFLAGS) -c util.cpp

clean:
	rm -f *.o client


#-std=c++11