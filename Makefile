# change the settings according to your compiler
CC=gcc
CFLAGS=-std=c99 -Wall
LFLAGS=-L. -lmosquitto -pthread -lcrypto -lssl

all: mqtt_client

mqtt_client: client.o main.o queue.o utils.o
	$(CC) -o mqtt_client client.o main.o queue.o utils.o $(LFLAGS)

client.o: client.c client.h
	$(CC) $(CFLAGS) -c client.c

main.o: main.c client.h queue.h utils.h mosquitto.h
	$(CC) $(CFLAGS) -c main.c -I.

queue.o: queue.c queue.h
	$(CC) $(CFLAGS) -c queue.c

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c utils.c

clean:
	rm -rf mqtt_client client.o main.o queue.o utils.o
