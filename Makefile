all: server client

server: server.o yyjson.o exception.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

client: client.o yyjson.o exception.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

client.o: client.c yyjson.h exception.h
	$(CC) $(CFLAGS) -c -o $@ client.c

server.o: server.c yyjson.h exception.h
	$(CC) $(CFLAGS) -c -o $@ server.c

yyjson.o: yyjson.c yyjson.h
	$(CC) $(CFLAGS) -c -o $@ yyjson.c

exception.o: exception.c exception.h
	$(CC) $(CFLAGS) -c -o $@ exception.c

clean:
	rm *.o