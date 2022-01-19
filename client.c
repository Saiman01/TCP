#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h> 
#include <time.h>

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

//function to calculate the checksum
unsigned short int  CalculateChecksum(unsigned short int cksum_arr[140]){
unsigned int i,sum=0, cksum, wrap;	
for ( i=0;i<140;i++)            // Compute sum
  {
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
int sockfd;
int len = sizeof(struct sockaddr);
char response[200];
struct sockaddr_in servaddr;
unsigned short int cksum_arr[140];
 srand(time(NULL));
FILE *fptr;
fptr = fopen("client.log", "a");	
//error check
if (argc != 2) {
	printf("Enter port number\n");
		exit(1);
	}


/* AF_INET - IPv4 IP , Type of socket, protocol*/
if((sockfd=socket(AF_INET, SOCK_STREAM, 0))<0)
{
	die("Socket Creation Error");
}	

bzero(&servaddr,sizeof(servaddr));

servaddr.sin_family = AF_INET;
servaddr.sin_port = htons(atoi(argv[1])); // Server port number

/* Convert IPv4 and IPv6 addresses from text to binary form */
inet_pton(AF_INET,"129.120.151.95",&(servaddr.sin_addr));

/* Connect to the server */
if(connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr)) < 0) {
	die("Connection failed");	
}

//populate TCP Segmenr
getsockname(sockfd,(struct sockaddr *)&servaddr, &len);
tcpSeg.src = ntohs(servaddr.sin_port);//source port
tcpSeg.des = atoi(argv[1]); 
//populating sequence number with random number ranging from 1 to 512
tcpSeg.seq = rand() % 512+1;
tcpSeg.ack = 0; 
//setting payload to zero
bzero(tcpSeg.data, 256); 
tcpSeg.hdr_flags = 0x6000;
tcpSeg.rec = 0; 
tcpSeg.cksum = 0;  //Needs to be computed  
tcpSeg.ptr = 0;  
tcpSeg.opt = 0;

//setting SYN bit as high
tcpSeg.hdr_flags = 0x6000 + 0x0002; 
memcpy(cksum_arr, &tcpSeg, 280); // Copying 280 bytes
tcpSeg.cksum = CalculateChecksum(cksum_arr); 

//printf("\n----Header Segment with SYN flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
 

//unsigned short int temp = tcpSeg.cksum;
if(send(sockfd, &tcpSeg, sizeof(tcpSeg), 0) <0) {
	die("Error sending\n"); 
}

bzero(&tcpSeg, sizeof(tcpSeg));
if(recv(sockfd , &tcpSeg , sizeof(tcpSeg), 0) < 0)
{
	die("Receieve error for SYN-ACK Segment\n");

}

printf("\n----Header Segment with SYN and ACK flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
fprintf(fptr,"\n----Header Segment with SYN and ACK flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum); 

memcpy(cksum_arr, &tcpSeg, 280); // Copying 280 bytes
unsigned int temp = tcpSeg.seq;
//calculate and store checksum
tcpSeg.cksum = CalculateChecksum(cksum_arr);
 
if(tcpSeg.cksum==0) {
	 if(tcpSeg.hdr_flags == 0x6012){
	 tcpSeg.seq = tcpSeg.ack; 
	 tcpSeg.ack =  temp + 1; 
	 //setting only ack as high
	 tcpSeg.hdr_flags = tcpSeg.hdr_flags - 0x0002;
	 memcpy(cksum_arr, &tcpSeg, 280); // Copying 280 bytes
	 tcpSeg.cksum = CalculateChecksum(cksum_arr);
//	 printf("\n----Header Segment ACK flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
	if(send(sockfd, &tcpSeg, sizeof(tcpSeg), 0) <0) {
        die("Error sending\n");
	}
	}
}

if(recv(sockfd , response , sizeof(response), 0) < 0)
{
        die("Receieve error for response\n");

}

printf("%s", response); 
fprintf(fptr, "%s", response);
bzero(response, sizeof(response)); 
temp  = 0; 
//------------------------------------------------------------CLOSING TCP CONNECTION------------------------------------------------------------------------------------------------------------------------

tcpSeg.cksum = 0; 
tcpSeg.seq = 256;
tcpSeg.ack =  128;
//default value
tcpSeg.hdr_flags = 0x6000; 
tcpSeg.hdr_flags = tcpSeg.hdr_flags + 0x0001; 
memcpy(cksum_arr, &tcpSeg, 280); // Copying 280 bytes
tcpSeg.cksum = CalculateChecksum(cksum_arr);
//printf("\n----Header Segment FIN flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
if(send(sockfd, &tcpSeg, sizeof(tcpSeg), 0) <0) {
die("Error sending\n");
}
bzero(&tcpSeg, sizeof(tcpSeg));
if(recv(sockfd , &tcpSeg , sizeof(tcpSeg), 0) < 0)
{
        die("Receieve error for SYN-ACK Segment\n");

}

printf("\n----Header Segment with ACK flag high -----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
fprintf(fptr,"\n----Header Segment with ACK flag high -----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
temp = tcpSeg.seq; 
memcpy(cksum_arr, &tcpSeg, 280);
tcpSeg.cksum = CalculateChecksum(cksum_arr);

if(tcpSeg.cksum==0) {
	if(tcpSeg.hdr_flags == 0x6010) {
		printf("The server has sent an acknowledgement for the close request, then waiting for the next segment... \n"); 
		fprintf(fptr,"The server has sent an acknowledgement for the close request, then waiting for the next segment... \n");
		bzero(&tcpSeg, sizeof(tcpSeg));
		if(recv(sockfd , &tcpSeg , sizeof(tcpSeg), 0) < 0)
		{
        	die("Receieve error for SYN-ACK Segment\n");

		}
		printf("\n----Header Segment FIN flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
		fprintf(fptr, "\n----Header Segment FIN flag high-----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum); 
		memcpy(cksum_arr, &tcpSeg, 280);
		tcpSeg.cksum = CalculateChecksum(cksum_arr);

		if(tcpSeg.cksum==0) {
			 if(tcpSeg.hdr_flags == 0x6001) {
				tcpSeg.ack = tcpSeg.seq+1;
			 	tcpSeg.seq = temp + 1; 
		 		  //only ack bit as high
                		tcpSeg.hdr_flags = tcpSeg.hdr_flags - 0x0001 + 0x0010;
	       			tcpSeg.cksum = 0; 
				memcpy(cksum_arr, &tcpSeg, 280);
                		tcpSeg.cksum = CalculateChecksum(cksum_arr);			
//				printf("\n----Header Segment with ACK flag high -----\nSource Port: %hu\nDestination Port: %hu\nSequence Number: %d\nAcknowledgement Number: %d\nHeader Flags: 0x%04X\nChecksum: 0x%04X\n\n", tcpSeg.src, tcpSeg.des, tcpSeg.seq, tcpSeg.ack, tcpSeg.hdr_flags, tcpSeg.cksum);
				if(send(sockfd, &tcpSeg, sizeof(tcpSeg), 0) <0) {
					die("Error sending\n");
				}
				sleep(2); 

			 }
		}

		}
}
fclose(fptr);
return 0;
}
