server: server.o yyjson.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

server.o: server.c
	$(CC) $(CFLAGS) -c -o $@ server.c

yyjson.o: yyjson.c
	$(CC) $(CFLAGS) -c -o $@ yyjson.c

clean:
	rm *.o