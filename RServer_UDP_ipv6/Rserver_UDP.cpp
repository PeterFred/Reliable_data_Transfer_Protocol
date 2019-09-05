//159.334 - Networks
// SERVER: prototype for assignment 2.
//Note that this progam is not yet cross-platform-capable
// This code is different than the one used in previous semesters...
//************************************************************************/
//RUN WITH: Rserver_UDP 1235 0 0
//RUN WITH: Rserver_UDP 1235 1 0 
//RUN WITH: Rserver_UDP 1235 0 1 
//RUN WITH: Rserver_UDP 1235 1 1  
//************************************************************************/

//Ws2_32.lib
#define _WIN32_WINNT 0x501  //to recognise getaddrinfo()

//"For historical reasons, the Windows.h header defaults to including the Winsock.h header file for Windows Sockets 1.1. The declarations in the Winsock.h header file will conflict with the declarations in the Winsock2.h header file required by Windows Sockets 2.0. The WIN32_LEAN_AND_MEAN macro prevents the Winsock.h from being included by the Windows.h header"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <iostream>

#include "myrandomizer.h" 

using namespace std;

#define BUFFER_SIZE 80  //used by receive_buffer and send_buffer
                        //the BUFFER_SIZE needs to be at least big enough to receive the packet
#define SEGMENT_SIZE 78

#define WSVERS MAKEWORD(2,0)
WSADATA wsadata;

const int ARG_COUNT=4;
int numOfPacketsDamaged=0;
int numOfPacketsLost=0;
int numOfPacketsUncorrupted=0;

int packets_damagedbit=0;
int packets_lostbit=0;

//********************************************************************
// CRC Generator
//********************************************************************
#define GENERATOR 0x8005 //0x8005, generator for polynomial division

unsigned int CRCpolynomial(char *buffer){
	unsigned char i;
	unsigned int rem=0x0000;
    unsigned int bufsize=strlen(buffer);
	while(bufsize--!=0){
		for(i=0x80;i!=0;i/=2){
			if((rem&0x8000)!=0){
				rem=rem<<1;
				rem^=GENERATOR;
			}
     		else{
	   	   rem=rem<<1;
		   }
	  		if((*buffer&i)!=0){
			   rem^=GENERATOR;
			}
		}
		buffer++;
	}
	rem=rem&0xffff;
	return rem;
}
//********************************************************************

//*******************************************************************
//Function to save lines and discard the header
//*******************************************************************
//You are allowed to change this. You will need to alter the NUMBER_OF_WORDS_IN_THE_HEADER if you add a CRC
#define NUMBER_OF_WORDS_IN_THE_HEADER 2 //DON'T CHANGE THIS! (Peter)
/*>>>>>>If you change this you will need to re-implement the getCRC function, all the
sprintf's and the send / receive buffers */

void save_line_without_header(char * receive_buffer,FILE *fout){
	//char *sep = " "; //separator is the space character
	char sep[3];

	strcpy(sep," "); //separator is the space character
	char *word;
	int wcount=0;
	char dataExtracted[BUFFER_SIZE]="\0";

	// strtok remembers the position of the last token extracted.
	// strtok is first called using a buffer as an argument.
	// successive calls requires NULL as an argument.
	// the function remembers internally where it stopped last time

	
	//loop while word is not equal to NULL.
	for (word = strtok(receive_buffer, sep); word; word = strtok(NULL, sep))
	{
		wcount++;
		if(wcount > NUMBER_OF_WORDS_IN_THE_HEADER){ //if the word extracted is not part of the header anymore
			strcat(dataExtracted, word); //extract the word and store it as part of the data
			strcat(dataExtracted, " "); //append space
		}
	}

	dataExtracted[strlen(dataExtracted)-1]=(char)'\0'; //get rid of last space appended
	printf("DATA: %s, %d elements\n",dataExtracted,int(strlen(dataExtracted)));

	//make sure that the file pointer has been properly initialised
	if (fout!=NULL) fprintf(fout,"%s\n",dataExtracted); //write to file
	else {
		printf("Error in writing to write...\n");
		exit(1);
		}
}

/*
 * A method that extracts the CRC from the receive buffer and removes it.
 * It then gets a CRC for the receive_buffer, and compares the two.
 * If they are the same, it returns true. If they are not it retruns false.
 */

bool getCRC(char *receive_buffer){
	char CRC[10], temp_buffer[BUFFER_SIZE];
	unsigned int CRCresult;

	//Extract the CRC
	int i=0;
	while(receive_buffer[i] != ' '){
		CRC[i] = receive_buffer[i];
		i++;
	}
	CRC[i] = '\0'; //Complete the string

	i++; //Skip the trailing space

	//Remove the CRC from the receive_buffer
	strcpy(temp_buffer, receive_buffer);
	memset(receive_buffer, 0, 80);

	int j=0;
	while(temp_buffer[i] != '\0'){
		receive_buffer[j] =temp_buffer[i];
		j++;
		i++;
	}
	receive_buffer[j]='\0';

	memset(temp_buffer, 0, sizeof(temp_buffer)); 	//clean up the temp_buffer 

	CRCresult = CRCpolynomial(receive_buffer); 		//Get a CRC for the receive_buffer
	sprintf(temp_buffer, "%X",CRCresult);			//Copy it to a string for comparison

	//Compare the two stings to see if they are the same, and return the result
	if(strcmp(temp_buffer, CRC)==0){ 
		return true;
	}else{
		return false;
	}
}


/////////////////////////////////////////////////////////////////////
//*******************************************************************
//MAIN
//*******************************************************************
/////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[]) {

	//********************************************************************
	// INITIALIZATION
	//********************************************************************
	struct sockaddr_storage clientAddress; //IPv4 & IPv6 -compliant
	struct addrinfo *result = NULL;
    struct addrinfo hints;
	int iResult;
	
	memset(&clientAddress, 0, sizeof(clientAddress));  //clean up

    SOCKET s;
    char send_buffer[BUFFER_SIZE],receive_buffer[BUFFER_SIZE], temp_buffer[BUFFER_SIZE];
    int n,bytes,addrlen;

	memset(&hints, 0, sizeof(struct addrinfo));
	 
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE; // For wildcard IP address 
	
	
    randominit();
	//********************************************************************
	// WSSTARTUP
	//********************************************************************
	if (WSAStartup(WSVERS, &wsadata) != 0) {
    	WSACleanup();
      	printf("WSAStartup failed\n");
   	}
	
	if (argc != ARG_COUNT) {
		printf("USAGE: Rserver_UDP localport allow_corrupted_bits(0 or 1) allow_packet_loss(0 or 1)\n");
	   	exit(1);
   	}
   
	iResult = getaddrinfo(NULL, argv[1], &hints, &result); //converts human-readable text strings representing hostnames or IP addresses 
	                                                        //into a dynamically allocated linked list of struct addrinfo structures
																			  //IPV4 & IPV6-compliant
	if (iResult != 0) {
    	printf("getaddrinfo failed: %d\n", iResult);
    	WSACleanup();
    	return 1;
   	}	
	
	//********************************************************************
	//SOCKET
	//********************************************************************
   	s = INVALID_SOCKET; //socket for listening
	// Create a SOCKET for the server to listen for client connections

	s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	//check for errors in socket allocation
	if (s == INVALID_SOCKET) {
		printf("Error at socket(): %d\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		exit(1);//return 1;
	}
	
   	packets_damagedbit=atoi(argv[2]);
   	packets_lostbit=atoi(argv[3]);
   	if (packets_damagedbit < 0 || packets_damagedbit > 1 || packets_lostbit < 0 || packets_lostbit > 1){
		printf("USAGE: Rserver_UDP localport allow_corrupted_bits(0 or 1) allow_packet_loss(0 or 1)\n");
		exit(0);
   	}
      
   	
	//********************************************************************
	//BIND
	//********************************************************************
   	iResult = bind( s, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
    	printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result); 
        closesocket(s);
        WSACleanup();
        return 1;
    }

    cout << "==============<< UDP SERVER >>=============" << endl;
    cout << "channel can damage packets=" << packets_damagedbit << endl;
    cout << "channel can lose packets=" << packets_lostbit << endl;
	 
	freeaddrinfo(result); //free the memory allocated by the getaddrinfo 
	                       //function for the server's address, as it is 
	                       //no longer needed
	//********************************************************************
	// Open file to save the incoming packets
	//********************************************************************
	//In text mode, carriage return–linefeed combinations 
	//are translated into single linefeeds on input, and 
	//linefeed characters are translated to carriage return–linefeed combinations on output.    
	FILE *fout=fopen("data_received.txt","w"); 
	
	int pktNumber=0; 
	int expectedSeqNum = 0; //expectedSeNum for the next packet

	//******************************************************************** 
	//INFINITE LOOP
	//********************************************************************
   	while (1) {
		//********************************************************************
		//RECEIVE
		//********************************************************************	
		addrlen = sizeof(clientAddress); //IPv4 & IPv6-compliant
		memset(receive_buffer,0,sizeof(receive_buffer));
		bytes = recvfrom(s, receive_buffer, SEGMENT_SIZE, 0, (struct sockaddr*)&clientAddress, &addrlen);

		//********************************************************************
		//IDENTIFY UDP client's IP address and port number.     
		//********************************************************************      
		char clientHost[NI_MAXHOST]; 
   		char clientService[NI_MAXSERV];	
    	memset(clientHost, 0, sizeof(clientHost));
    	memset(clientService, 0, sizeof(clientService));
    	bool notCorrupt=true;
    	unsigned int notCorruptACK;

    	getnameinfo((struct sockaddr *)&clientAddress, addrlen,
        			clientHost, sizeof(clientHost),
                  	clientService, sizeof(clientService),
                  	NI_NUMERICHOST);
    	printf("\n================================================\n");	
    	printf("\nReceived a packet of size %d bytes from <<<UDP Client>>> with IP address:%s, at Port:%s\n",bytes,clientHost, clientService); 	   
		
		//********************************************************************
		//PROCESS RECEIVED PACKET
		//********************************************************************
		
		//Remove trailing CR and LF
		n=0;
		while(n < bytes){
			n++;
			if ((bytes < 0) || (bytes == 0)) break;
			if (receive_buffer[n] == '\n') { /*end on a LF*/
				receive_buffer[n] = '\0';
				break;
			}
			if (receive_buffer[n] == '\r') {/*ignore CRs*/
				receive_buffer[n] = '\0';
			}
		}
		
		//if ((bytes < 0) || (bytes == 0)) break;

		printf("RECEIVED --> %s \n",receive_buffer);

		//Check if packet was corrupted			
		notCorrupt = getCRC(receive_buffer);

		if(notCorrupt){
			if (strncmp(receive_buffer,"PACKET",6)==0)  {
				sscanf(receive_buffer, "PACKET %d",&pktNumber);
				if(expectedSeqNum == pktNumber){ //Uncorrupted package, in correct order
					expectedSeqNum++;
					
					//********************************************************************
					//PREPARE ACK
					//********************************************************************
					
					sprintf(send_buffer,"ACK %d",pktNumber);
					
					//*******************************************************************
					//CRC added to begining of ACK packet and sent
					//*******************************************************************
					notCorruptACK =CRCpolynomial(send_buffer);	//Get a CRC for the ACK
					sprintf(temp_buffer, "%X ",notCorruptACK);	//Create packet with CRC and Hex value
					strcat(temp_buffer,send_buffer);   			//append CRC to ACK

					strcat(temp_buffer, "\r\n");

					strcpy(send_buffer,temp_buffer);   			//the complete ACK packet with CRC header

					send_unreliably(s,send_buffer,(sockaddr*)&clientAddress ); //send ACK ureliably 

					//**************************************************
					//store the packet's data into a file (note CRC removed)
					//**************************************************
					save_line_without_header(receive_buffer,fout); 

				}else{
					//Packet out of sequence.
					//Send ACK of expectedSeqNum

					//********************************************************************
					//PREPARE ACK
					//********************************************************************
											
					sprintf(send_buffer,"ACK %d",(expectedSeqNum-1));
					
					//*******************************************************************
					//CRC added to begining of ACK packet and sent
					//*******************************************************************
					notCorruptACK =CRCpolynomial(send_buffer);	//Get a CRC for the ACK
					sprintf(temp_buffer, "%X ",notCorruptACK);	//Create packet with CRC and Hex value
					strcat(temp_buffer,send_buffer);   			//append CRC to ACK

					strcat(temp_buffer, "\r\n");				//Append \r\n
					strcpy(send_buffer,temp_buffer);   			//the complete ACK packet with CRC header

					send_unreliably(s,send_buffer,(sockaddr*)&clientAddress ); //send ACK ureliably 
				}

			}else if (strncmp(receive_buffer,"CLOSE",5)==0)  {//if client says "CLOSE", the last packet for the file was sent. Close the file
				//Remember that the packet carrying "CLOSE" may be lost or damaged as well!
				fclose(fout);
				
				printf("Server saved data_received.txt \n");//you have to manually check to see if this file is identical to file1_Windows.txt
				printf("Closing the socket connection and Exiting...\n");


				//If the acknoledgment gets lost there is no way to know, as there will not be 
				//an acknowledgement back. Either can do a timeout, which takes time, or just 
				//send three packets and hope for the best. Could possibly put a wait in between
				//each one to account for transmission corruption?

				for(int i=0; i<3; i++){
					sprintf(send_buffer,"ACK CLOSE");
					//*******************************************************************
					//CRC added to begining of ACK packet and sent
					//*******************************************************************
					notCorruptACK =CRCpolynomial(send_buffer);	//Get a CRC for the ACK
					sprintf(temp_buffer, "%X ",notCorruptACK);	//Create packet with CRC and Hex value
					strcat(temp_buffer,send_buffer);   			//append CRC to ACK

					strcat(temp_buffer, "\r\n");
					strcpy(send_buffer,temp_buffer);   			//the complete ACK packet with CRC header

					send_unreliably(s,send_buffer,(sockaddr*)&clientAddress ); //send ACK ureliably
				} 
				closesocket(s);
				break;
			}
		}else if((expectedSeqNum-1) >= 0){
			//CORRUPTED PACKET (Not Packet 0)
			//********************************************************************
			//PREPARE ACK
			//********************************************************************
			sprintf(send_buffer,"ACK %X",(expectedSeqNum-1));

			//*******************************************************************
			//CRC added to begining of ACK packet and sent
			//*******************************************************************
			notCorruptACK =CRCpolynomial(send_buffer);	//Get a CRC for the ACK
			sprintf(temp_buffer, "%X ",notCorruptACK);	//Create packet with CRC and Hex value
			strcat(temp_buffer,send_buffer);   			//append CRC to ACK
			strcat(temp_buffer, "\r\n");				//Append \r\n
			strcpy(send_buffer,temp_buffer);   			//the complete ACK packet with CRC header

			send_unreliably(s,send_buffer,(sockaddr*)&clientAddress ); //send ACK ureliably 

			cout<<"CORRUPTED PACKET.\nACK of last succesful packet ("<<expectedSeqNum-1<<") sent.\nWait for new packet"<<endl;
		}else{
			//If it is the first packet that is corrupted, wait for a timeout from the client.
			cout<<"CORRUPTED PACKET.\nWait for new packet"<<endl;
		}	
   }
   closesocket(s);

   cout << "==============<< SERVER STATISTICS >>=============" << endl;
   cout << "numOfPacketsDamaged=" << numOfPacketsDamaged << endl;
   cout << "numOfPacketsLost=" << numOfPacketsLost << endl;
   cout << "numOfPacketsUncorrupted=" << numOfPacketsUncorrupted << endl;
   cout << "===========================================" << endl;

   exit(0);
}
