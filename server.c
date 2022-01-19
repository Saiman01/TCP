#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h> 
#include <time.h>
#include <arpa/inet.h>

struct tcp_hdr{
                unsigned short int src;
                unsigned short int des;
                unsigned int seq;
                unsigned int ack;
                unsigned short int hdr_flags;
                unsigned short int rec;
                unsigned short int cksum;
                unsigned short int ptr;
                unsigned int opt;
                char data [256];
};

//function to calculate checksum
unsigned short int  CalculateChecksum(unsigned short int cksum_arr[140]){
unsigned int i,sum=0, cksum=0, wrap=0;
for ( i=0;i<140;i++)            // Compute sum
  {
    // printf("0x%04X\n", cksum_arr[i]);
         sum = sum + cksum_arr[i];
  }

  wrap = sum >> 16;             // Get the carry
  sum = sum & 0x0000FFFF;       // Clear the carry bits
  sum = wrap + sum;             // Add carry to the sum

  wrap = sum >> 16;             // Wrap around once more as the previous sum could have generated a carry
  sum = sum & 0x0000FFFF;
  cksum = wrap + sum;

  return(0xFFFF^cksum);
}


void die(char *s)
{
	perror(s);
	exit(1);
}

int main (int argc, char *argv[])
{
struct tcp_hdr tcpSeg;
unsigned short int cksum_arr[140];
unsigned int i,sum=0, cksum, wrap;
int listen_fd, conn_fd;    
int len = sizeof(struct sockaddr);
char response[200];
struct sockaddr_in servaddr;
srand(time(NULL));
FILE *fptr; 
fptr = fopen("server.log", "a"); //opening file to write

//command line argument test
if (argc != 2) {
	printf("Enter port number\n");
	die("Port No");
}

/* AF_INET - IPv4 IP , Type of socket, protocol*/
listen_fd = socket(AF_INET, SOCK_STREAM, 0);

bzero(&servaddr, sizeof(servaddr));

servaddr.sin_family = AF_INET;
servaddr.sin_addr.s_addr = htons(INADDR_ANY);
servaddr.sin_port = htons(atoi(argv[1]));

/* Binds the above details to the socket */
bind(listen_fd,  (struct sockaddr *) &servaddr, sizeof(servaddr));

/* Start listening to incoming connections */
listen(listen_fd, 10);

conn_fd = accept(listen_fd, (struct sockaddr*)NULL, NULL);

//recieve from client
if (recv(conn_fd, &tcpSeg, sizeof(tcpSeg), 0) < 0)
{
	die("SYN recieve error\n");		
} 

//print recieved segement into output and a file
printf("\n----Header Segment with SYN flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
fprintf(fptr, "\n----Header Segment with SYN flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);

memcpy(cksum_arr, &tcpSeg, 280); // Copying 280 bytes
//calculate and store checksum
tcpSeg.cksum = CalculateChecksum(cksum_arr);

//if the checksum matches and the appropriate flag is high
if (tcpSeg.cksum==0) {
	if(tcpSeg.hdr_flags == 0x6002){
	tcpSeg.ack = tcpSeg.seq+1;
	tcpSeg.seq = rand() % 512+1;
	//ack bit and syn bit 1
	tcpSeg.hdr_flags = tcpSeg.hdr_flags + 0x0010;
	memcpy(cksum_arr, &tcpSeg, 280); // Copying 280 bytes
	//calculate and store checksum
	tcpSeg.cksum = CalculateChecksum(cksum_arr);
//	printf("\n----Header Segment with SYN and ACK flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
	if(send(conn_fd, &tcpSeg, sizeof(tcpSeg), 0) <0) {
        die("Error sending\n");
	}
	}	
}
 

bzero(&tcpSeg, sizeof(tcpSeg));
if (recv(conn_fd, &tcpSeg, sizeof(tcpSeg), 0) < 0)
{
        die("ACK recieve error\n");
}
printf("\n----Header Segment ACK flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
fprintf(fptr, "\n----Header Segment ACK flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);

memcpy(cksum_arr, &tcpSeg, 280); // Copying 280 bytes
tcpSeg.cksum = CalculateChecksum(cksum_arr);
if (tcpSeg.cksum==0) {
	if (tcpSeg.hdr_flags == 0x6010) {
		printf("Connection established\n");
		fprintf(fptr,"Connection established\n");  
	       	sprintf(response,"Connection established\n"); 
		 if(send(conn_fd, response, sizeof(response), 0) <0) {
	        die("Error sending\n");
	}
	
	}	
}

//------------------------------------------------------------CLOSING TCP CONNECTION------------------------------------------------------------------------------------------------------------------------
fflush(stdout); 
bzero(cksum_arr, sizeof(cksum_arr)); 
bzero(&tcpSeg, sizeof(tcpSeg));
if (recv(conn_fd, &tcpSeg, sizeof(tcpSeg), 0) < 0)
{
        die("FIN recieve error\n");
}

printf("\n----Header Segment FIN flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
fprintf(fptr, "\n----Header Segment FIN flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);

memcpy(cksum_arr, &tcpSeg, 280); // Copying 280 bytes
tcpSeg.cksum = CalculateChecksum(cksum_arr); 
if (tcpSeg.cksum==0) {
        if (tcpSeg.hdr_flags == 0x6001) {
                tcpSeg.ack = tcpSeg.seq+1; 
		tcpSeg.seq = 128;
		//only ack bit as high
		tcpSeg.hdr_flags = tcpSeg.hdr_flags - 0x0001 + 0x0010;
		 memcpy(cksum_arr, &tcpSeg, 280); // Copying 280 bytes
        	//calculate and store checksum
        	tcpSeg.cksum = CalculateChecksum(cksum_arr);
//		printf("\n----Header Segment with ACK flag high -----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
		if(send(conn_fd, &tcpSeg, sizeof(tcpSeg), 0) <0) {
        	die("Error sending\n");
		}
	}

}

tcpSeg.ack = tcpSeg.seq+1;
tcpSeg.seq = 128;
//setting fin bit as high
tcpSeg.hdr_flags = tcpSeg.hdr_flags - 0x0010 + 0x0001;
tcpSeg.cksum = 0; 
memcpy(cksum_arr, &tcpSeg, 280); // Copying 280 bytes
tcpSeg.cksum = CalculateChecksum(cksum_arr);
//printf("\n----Header Segment FIN flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
if(send(conn_fd, &tcpSeg, sizeof(tcpSeg), 0) <0) {
	die("Error sending\n");
}
bzero(&tcpSeg, sizeof(tcpSeg));
if (recv(conn_fd, &tcpSeg, sizeof(tcpSeg), 0) < 0)
{
        die("ACK recieve error\n");
}

unsigned short int temp; 
temp = tcpSeg.cksum; 
memcpy(cksum_arr, &tcpSeg, 280); // Copying 280 bytes
tcpSeg.cksum = CalculateChecksum(cksum_arr);
if (tcpSeg.cksum==0) {
        if (tcpSeg.hdr_flags == 0x6010) {
		printf("\n----Header Segment with ACK flag high -----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, temp);
		fprintf(fptr, "\n----Header Segment with ACK flag high -----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, temp);
		printf("Connection Closed\n"); 
		fprintf(fptr, "Connection Closed\n"); 
	}
}

return 0; 
}




