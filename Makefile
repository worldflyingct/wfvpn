all: server client

server: server.o yyjson.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

client: client.o yyjson.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

client.o: client.c
	$(CC) $(CFLAGS) -c -o $@ client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o $@ server.c

yyjson.o: yyjson.c
	$(CC) $(CFLAGS) -c -o $@ yyjson.c

clean:
	rm *.o