all:  server client

server: 
	gcc server.c -o tserver

client: 
	gcc client.c -o tclient 

clean: 
	rm -rf tserver tclient


