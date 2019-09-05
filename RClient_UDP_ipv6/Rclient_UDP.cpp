//159.334 - Networks
// CLIENT: prototype for assignment 2. 
//Note that this progam is not yet cross-platform-capable
// This code is different than the one used in previous semesters...
//************************************************************************/
//RUN WITH: Rclient_UDP 127.0.0.1 1235 0 0 
//RUN WITH: Rclient_UDP 127.0.0.1 1235 0 1 
//RUN WITH: Rclient_UDP 127.0.0.1 1235 1 0 
//RUN WITH: Rclient_UDP 127.0.0.1 1235 1 1 
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
#include <time.h>


#include "myrandomizer.h"

using namespace std;

#define WSVERS MAKEWORD(2,0)
#define BUFFER_SIZE 80  //used by receive_buffer and send_buffer
                        //the BUFFER_SIZE has to be at least big enough to receive the packet
#define SEGMENT_SIZE 78
//segment size, i.e., if fgets gets more than this number of bytes it segments the message into smaller parts.

#define TIMEOUT 2 //Change this to adjust the timeout. Note, needs to be at least 2.

WSADATA wsadata;
const int ARG_COUNT=5;
//---
int numOfPacketsDamaged=0;
int numOfPacketsLost=0;
int numOfPacketsUncorrupted=0;

int packets_damagedbit=0;
int packets_lostbit=0;


//*******************************************************************
//WAIT
//*******************************************************************

void wait(int seconds){
	clock_t endWait;
	endWait = clock() +seconds *CLOCKS_PER_SEC;
	while(clock()<endWait){}
}

clock_t	startTime, elapsedTime;


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
	
	//*******************************************************************
	// Initialization
	//*******************************************************************
	struct sockaddr_storage localaddr, remoteaddr;
	char portNum[NI_MAXSERV];
	struct addrinfo *result = NULL;
	struct addrinfo hints;

	memset(&localaddr, 0, sizeof(localaddr));  //clean up
	memset(&remoteaddr, 0, sizeof(remoteaddr));//clean up  
	randominit();
	
	SOCKET s;
	char send_buffer[BUFFER_SIZE],receive_buffer[BUFFER_SIZE],file_buffer[BUFFER_SIZE][BUFFER_SIZE];
	int n,bytes,addrlen;
	   
	addrlen=sizeof(struct sockaddr);
		
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

		
	//********************************************************************
	// WSSTARTUP
	//********************************************************************
	if (WSAStartup(WSVERS, &wsadata) != 0) {
	    WSACleanup();
	    printf("WSAStartup failed\n");
	}
	//*******************************************************************
	//	Dealing with user's arguments
	//*******************************************************************
	if (argc != ARG_COUNT) {
		printf("USAGE: Rclient_UDP remote_IP-address remoteport allow_corrupted_bits(0 or 1) allow_packet_loss(0 or 1)\n");
		exit(1);
	}
		
	int iResult=0;
		
	sprintf(portNum,"%s", argv[2]);
	iResult = getaddrinfo(argv[1], portNum, &hints, &result);
	   
	packets_damagedbit=atoi(argv[3]);
	packets_lostbit=atoi(argv[4]);
	if (packets_damagedbit < 0 || packets_damagedbit > 1 || packets_lostbit< 0 || packets_lostbit>1){
		printf("USAGE: Rclient_UDP remote_IP-address remoteport allow_corrupted_bits(0 or 1) allow_packet_loss(0 or 1)\n");
	    exit(0);
	}
	   
	//*******************************************************************
	//CREATE CLIENT'S SOCKET 
	//*******************************************************************
	s = INVALID_SOCKET; 
	s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	if (s == INVALID_SOCKET) {
	    printf("socket failed\n");
		exit(1);
	}
	//nonblocking option
	// Set the socket I/O mode: In this case FIONBIO
	// enables or disables the blocking mode for the 
	// socket based on the numerical value of iMode.
	// If iMode = 0, blocking is enabled; 
	// If iMode != 0, non-blocking mode is enabled.
	u_long iMode=1;

	iResult=ioctlsocket(s,FIONBIO,&iMode);
	if (iResult != NO_ERROR){
		printf("ioctlsocket failed with error: %d\n", iResult);
		closesocket(s);
		WSACleanup();
		exit(0);
	}

	cout << "==============<< UDP CLIENT >>=============" << endl;
	cout << "channel can damage packets=" << packets_damagedbit << endl;
	cout << "channel can lose packets=" << packets_lostbit << endl;
		
	//*******************************************************************
	//SEND A TEXT FILE 
	//*******************************************************************
	
	char temp_buffer[BUFFER_SIZE];
	FILE *fin=fopen("data_for_transmission.txt","rb"); //original
		
	//In text mode, carriage return–linefeed combinations 
	//are translated into single linefeeds on input, and 
	//linefeed characters are translated to carriage return–linefeed combinations on output. 

	//Set up Go-Back-N protocol
	int N=4; 					//Window size
	int base = 0; 				//Base number
	int nextSequenceNumber = 0; //Next Sequence number
	
	unsigned int CRCresult; 	//Result from CRC Generator
	bool rcv_pck=true; 			//If received packet is correct
	int iFile=0; 				//file_buffer index
	char packageArr[3]={0,0,0}; //Extracted package number (in array)
	int ackNUM=0;				//Extracted package number (as an int)
	bool timeFlag=false;		//Flag to see if timer started
	bool closeFlag= false;		//Flag to time CLOSE command sent

		
	if(fin==NULL){
		printf("cannot open data_for_transmission.txt\n");
		closesocket(s);
	   	WSACleanup();
		exit(0);
	} else {
		printf("data_for_transmission.txt is now open for sending\n");
	}

	//*******************************************************************
	//Read from the file, add CRC, and store in file_buffer
	//*******************************************************************
	while(fgets(file_buffer[iFile],SEGMENT_SIZE,fin)!=NULL){

		int file_buffer_length, pure_content_length;
		file_buffer_length = strlen(file_buffer[iFile]);
		
		if(feof(fin)) {
			pure_content_length = file_buffer_length;
		} else {
			pure_content_length = file_buffer_length - 2;
		}

		char pure_content[BUFFER_SIZE];
		for(int i = 0; i < pure_content_length; ++i) {
			pure_content[i] = file_buffer[iFile][i];
		}
		pure_content[pure_content_length] = '\0';

		sprintf(temp_buffer,"PACKET %d ",iFile);  //create packet header with Sequence number
		strcat(temp_buffer,pure_content);
		memset(file_buffer[iFile], 0, sizeof(file_buffer[iFile]));
		strcpy(file_buffer[iFile],temp_buffer);   //the complete packet (excluding CRC)
		
		//***************************************************************
		//CRC added to begining of packet
		//***************************************************************
		memset(temp_buffer, 0, sizeof(temp_buffer));	//clean up the temp_buffer 

		CRCresult = CRCpolynomial(file_buffer[iFile]); 	//Get a Cyclic Redundancy Check (CheckSum)
		sprintf(temp_buffer, "%X ",CRCresult);			//Create packet with CRC and Hex value

		strcat(temp_buffer,file_buffer[iFile]);   	//append CRC to packet header
		strcat(temp_buffer, "\r\n");				//append \r\n to tep_buffer

		memset(file_buffer[iFile], 0, sizeof(file_buffer[iFile]));
		strcpy(file_buffer[iFile],temp_buffer);   //the complete packet

		//**************************************************************
		//PACKET FINISHED IN FILE BUFFER
		//**************************************************************
		iFile++;	//increase file_buffer index for next iteration
	}
	//******************************************************************

	fclose(fin);
	printf("End-of-File reached. \n"); 

	while (1){

		//*******************************************************************
		//Calculate elapsed time. If greater than TIMEOUT send packets until
		//caught up to the count. Then restart the timer.
		//*******************************************************************
		elapsedTime =(clock()-startTime)/CLOCKS_PER_SEC;
		if(elapsedTime>TIMEOUT){
			nextSequenceNumber=ackNUM+1;
			startTime=0;
		}

		memset(send_buffer, 0, sizeof(send_buffer));//clean up the send_buffer before reading the next line
		
		Sleep(1);  	//sleep for 1 millisecond	

		//*************************************************************
		// SEND THE PACKET IF WITHIN WINDOW SCOPE
		//**************************************************************
		if( (nextSequenceNumber< (base+N)) && (!closeFlag) && nextSequenceNumber < iFile){ //Within the window scope
			strcpy(send_buffer, file_buffer[nextSequenceNumber]);	//Copy the packet from the file_buffer to the send buffer
			cout<<"\n======================================================\n";
			//cout<<">>>>SEND BUFFER ["<<nextSequenceNumber<<"] = "<<send_buffer<<endl;
			cout << "calling send_unreliably, to deliver data of size " << strlen(send_buffer) << endl;
			send_unreliably(s,send_buffer,(result->ai_addr)); //send the packet to the unreliable data channel
			
			//Check if the nextSequenceNumber is at the start of the window (base).
			//If it is, start the timer (if not already done so)
			if(base==nextSequenceNumber){
			 	if(!timeFlag){				//Check timer not already set
				 	startTime=clock();		//Start Timer
				 	timeFlag=true;			//Set flag to true to stop timer being reset
				 }
			}
			++nextSequenceNumber; 
		}else{	
			//Window is full. Do nothing so data doesn't get loaded.
			//Wait for other packets to arrive, or trip the TIMEOUT	
			wait(1);
		} 																		
			
		//********************************************************************
		//RECEIVE
		//********************************************************************
		memset(receive_buffer, 0, sizeof(receive_buffer));//clean up the receive_buffer 
		addrlen = sizeof(remoteaddr); //IPv4 & IPv6-compliant
		bytes = recvfrom(s, receive_buffer, 78, 0,(struct sockaddr*)&remoteaddr,&addrlen);

		
		//********************************************************************
		//IDENTIFY server's IP address and port number.     
		//********************************************************************      
		char serverHost[NI_MAXHOST]; 
    	char serverService[NI_MAXSERV];	
    	memset(serverHost, 0, sizeof(serverHost));
    	memset(serverService, 0, sizeof(serverService));

    	getnameinfo((struct sockaddr *)&remoteaddr, addrlen,
        	serverHost, sizeof(serverHost),
            serverService, sizeof(serverService),
            NI_NUMERICHOST);
		
		

		//********************************************************************
		//PROCESS REQUEST
		//********************************************************************
		//Remove trailing CR and LN
		if( bytes != SOCKET_ERROR ){	
			n=0;
			while (n<bytes){
				n++;
				if ((bytes < 0) || (bytes == 0)) break;	
				if (receive_buffer[n] == '\n') { /*end on a LF*/
					receive_buffer[n] = '\0';
					break;
				}
				if (receive_buffer[n] == '\r') /*ignore CRs*/
					receive_buffer[n] = '\0';
			}
		}
		if(bytes>0) {
			printf("\nReceived a packet of size %d bytes from <<<UDP Server>>> with IP address:%s, at Port:%s\n",bytes,serverHost, serverService); 	   
			printf("RECEIVED --> %s, %d elements\n",receive_buffer, int(strlen(receive_buffer)));
		}
		
		//********************************************************************
		//HANDLE ACK
		//********************************************************************
		//Check received ACK packet is not corruptes, and remove CRC
		rcv_pck = getCRC(receive_buffer);

		//If the receiving ACK specifies close, then break from the loop
		if (strncmp(receive_buffer,"ACK CLOSE",8)==0)  {
			break;
		}

		if(rcv_pck){ 

			elapsedTime =(clock()-startTime)/CLOCKS_PER_SEC;
			
			//*******************************
			//Extract the package number
			//*******************************
			int i=4, j=0;
			while(receive_buffer[i] != '\0'){
				packageArr[j] = receive_buffer[i];
				i++; j++;
			}
			packageArr[j] = '\0';
			
			sscanf(packageArr, "%d", &ackNUM); //Convert to an int
			//**********************************
		
			base=ackNUM+1;	//Increase base by 1 from last acknowledged ACK number

			//*******************************
			//Handle Timer
			//*******************************
			if(base==nextSequenceNumber){
				startTime=0;			//Stop timer 
				timeFlag=false;			
			}else if(base<nextSequenceNumber){
				if(!timeFlag){ 			//Don't restart the timer if its already on
					startTime=clock();	//Strat timer
					timeFlag=true;
				}
			}
		}else{ //corrupted ACK
			if(!timeFlag){ //Don't restart the timer if its already on
				startTime=clock();	//Start the timer
				timeFlag=true;
			}

		}
		//********************************************************************
		//ACK NOW HANDLED
		//********************************************************************

		//***************************************************************************
		//FILE READY TO BE CLOSED (Note it doesn't close here. needs Close ACK first)
		//***************************************************************************
		if(ackNUM>=(iFile-1) || closeFlag) {

			memset(send_buffer, 0, sizeof(send_buffer)); 
			sprintf(send_buffer,"CLOSE"); //send a CLOSE command to the RECEIVER (Server)
			
			//*******************************************************************
			//CRC added to begining of ACK
			//*******************************************************************
			memset(temp_buffer, 0, sizeof(temp_buffer));//clean up the temp_buffer 
			
			CRCresult = CRCpolynomial(send_buffer); //Get a Cyclic Redundancy Check (CheckSum)
			sprintf(temp_buffer, "%X ",CRCresult);	//Create packet with CRC and Hex value

			strcat(temp_buffer,send_buffer);   //append CRC to packet header


			strcat(temp_buffer, "\r\n");

			memset(send_buffer, 0, sizeof(send_buffer)); 

			strcpy(send_buffer,temp_buffer);   //the complete packet

			printf("\n======================================================\n");
			send_unreliably(s,send_buffer,(result->ai_addr));
			
			closeFlag = true; //Set flag so that packets won't be sent until timeout occurs

			if(!timeFlag){ 			//Don't restart the timer if its already on
				startTime=clock();	//Start the timer
				timeFlag=true;
			}
		}	
		//*************************************************************************

	} //while loop
	
	//*******************************************************************
	//CLOSESOCKET   
	//*******************************************************************
   	closesocket(s);
   	WSACleanup();
   	printf("Closing the socket connection and Exiting...\n");
   	cout << "==============<< CLIENT STATISTICS >>=============" << endl;
   	cout << "numOfPacketsDamaged=" << numOfPacketsDamaged << endl;
   	cout << "numOfPacketsLost=" << numOfPacketsLost << endl;
   	cout << "numOfPacketsUncorrupted=" << numOfPacketsUncorrupted << endl;
   	cout << "===========================================" << endl;
   	exit(0);
}