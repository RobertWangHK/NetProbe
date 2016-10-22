#include<stdio.h>
#include<winsock2.h>
#include<ws2tcpip.h>
#include <string>
#include <iostream>
#include <vector>
#include <algorithm>
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <chrono>
#include <ctime>
#include <time.h>
#include <math.h>
#include "getopt.h"

#define DEFAULT_UPDATE_TIME 500
#define DEFAULT_HOST_NAME "localhost"
#define DEFAULT_PORT_NUM 4180
#define DEFAULT_PROTOCOL "UDP"
#define DEFAULT_BLOCK_SIZE 1000 // send message bsize
#define DEFAULT_DATA_RATE 1000
#define DEFAULT_TOTAL_NUM 0
#define DEFAULT_BIND_NAME INADDR_ANY
#define MAX_HOSTNAME 30;
#define SECOND_PER_MINUTE CLOCKS_PER_SEC

//Equivalent, you can also add "Ws2_32.lib" 
// at Project Properties->Linker->Input->Additional Dependencies
#pragma comment(lib, "Ws2_32.lib") 
using std::cout;
using std::string;
using std::endl;
using std::to_string;
using namespace std::chrono;

CRITICAL_SECTION CriticalSection;
int digit = 0;

struct thread_data {
	DWORD startTime = 0;
	DWORD currentTime = 0;
	double jitter = 0;
	double average = 0;
	DWORD updateTime = 0; //time interval to update status
	int packetSize = 0;
	int packaccu = 0; //number of total received packages.
	long long packno = 0; //number of total sent packages.
	int packrec = 0; //number of total packages received
	int packlost = 0; //number of lost packages
};

struct thread_data context;

DWORD WINAPI SendThread(LPVOID lpParam);
DWORD WINAPI RecvThread(LPVOID lpParam);

int main(int argc, char *argv[])
{

	//std::time_t startTime = std::time(nullptr);
	InitializeCriticalSection(&CriticalSection);
	//DWORD startTime = clock();
	DWORD startTime = GetTickCount();
	EnterCriticalSection(&CriticalSection);
	context.startTime = startTime;
	LeaveCriticalSection(&CriticalSection);

	//WaitForMultipleObjects(1,&thread,TRUE,INFINITE);

	WORD version = MAKEWORD(2, 2);
	WSADATA wsa_data;
	int error;
	string mode;
	string attr;
	string value;

	DWORD updateTime = DEFAULT_UPDATE_TIME;
	int pktSize = DEFAULT_BLOCK_SIZE;
	int pktRate = DEFAULT_DATA_RATE;
	int pktNum = DEFAULT_TOTAL_NUM;
	int bufferSize = 10000;
	//string lHost = DEFAULT_BIND_NAME;
	string lHost = "INADDR_ANY";
	string rHost = DEFAULT_HOST_NAME;
	string rPort = to_string(DEFAULT_PORT_NUM);
	string lPort = to_string(DEFAULT_PORT_NUM);
	string protocol = DEFAULT_PROTOCOL;

	error = WSAStartup(version, &wsa_data);
	if (error != 0)
	{
		printf("WSAStartup failed with error=%d\n", error);
		WSACleanup();
		return -1;
	}
	if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2)
	{
		printf("cannot find winsock 2.2\n");
		WSACleanup();
		return -1;
	}

	static struct option long_options[] =
	{
		{ "stat", required_argument, 0, 1 },
		{ "rhost", required_argument, 0, 2 },
		{ "rport", required_argument, 0, 3 },
		{ "proto", required_argument, 0, 4 },
		{ "pktsize", required_argument, 0, 5 },
		{ "pktrate", required_argument, 0, 6 },
		{ "pktnum", required_argument, 0, 7 },
		{ "sbufsize", required_argument, 0, 8 },
		{ "send", no_argument, 0, 9 },
		{ "recv", no_argument, 0, 10 },
		{ "host", no_argument, 0, 11 },
		{ "lhost", required_argument, 0, 12 },
		{ "lport", required_argument, 0, 13 },
		{ "rbufsize", required_argument, 0, 14 },
		{ 0, 0, 0, 0 }
	};
	int c;
	while ((c = getopt_long_only(argc, argv, "", long_options, 0)) != -1)
	{
		switch (c)
		{
		case 1:
			updateTime = atoi(optarg);
			break;
		case 2:
			rHost = string(optarg);
			break;
		case 3:
			rPort = string(optarg);
			break;
		case 4:
			protocol = string(optarg);
			if (protocol != "UDP" && protocol != "TCP")
			{
				cout << "-proto TCP/UDP" << endl;
				return -1;
			}
			break;
		case 5:
			pktSize = atoi(optarg);
			break;
		case 6:
			pktRate = atoi(optarg);
			break;
		case 7:
			pktNum = atoi(optarg);
			break;
		case 8:
			bufferSize = atoi(optarg);
			break;
		case 9:
			mode = "send";
			break;
		case 10:
			mode = "recv";
			break;
		case 11:
			mode = "host";
			break;
		case 12:
			lHost = string(optarg);
			break;
		case 13:
			lPort = string(optarg);
			break;
		case 14:
			bufferSize = atoi(optarg);
			break;
		default:
			break;
		}
	}
	if (mode.compare("host") == 0) {
		char *pRemoteHost;
		pRemoteHost = new char[value.length() + 1];
		strcpy(pRemoteHost, value.c_str());
		struct hostent *pHost = NULL;
		switch (argc)
		{
		case 2:
			pRemoteHost = DEFAULT_HOST_NAME;
			break;
		case 3:
			value = string(argv[2]);
			pRemoteHost = new char[value.length() + 1];
			strcpy(pRemoteHost, value.c_str());
			break;
		default:
			printf("too many parameters for -host");
			return 0;
		}

		// Step 1: Determine if the it is a hostname or an IP address in dot notation.
		unsigned long ipaddr = inet_addr(pRemoteHost);
		if (ipaddr != -1) { // It is an IP address, reverse lookup the hostname first.
			pHost = gethostbyaddr((char *)(&ipaddr), sizeof(ipaddr), AF_INET);
			if ((pHost != NULL) && (pHost->h_name)) {
				strncpy(pRemoteHost, pHost->h_name, 30);
				pRemoteHost[29] = 0; // Guarantee null-termination
			}
			else if (
				WSAGetLastError() == WSANO_DATA) {
				printf("\n No DNS Record for the IP address found.");
				return 0;
			}
			else {
				printf("\n gethostbyaddr() failed with code %i\n", WSAGetLastError());
				return 0;
			}
		}
		// Step 2: Resolve the hostname in pRemoteHost.
		pHost = gethostbyname(pRemoteHost);
		if (pHost != NULL) { // Successful
			printf("host information mode\n");
			printf("Official name : %s\n", (pHost->h_name) ? (pHost->h_name) : "NA");
			//printf("\n Official IP : %s", pRemoteHost);
			char *ptr = pHost->h_aliases[0];
			int i = 0;
			while (ptr) {
				printf("Alias %i       : %s\n", i + 1, pHost->h_aliases[i]);
				ptr = pHost->h_aliases[++i];
			}
			ptr = pHost->h_addr_list[0]; i = 0;
			while (ptr) {
				printf("IP Address %i  : %s\n", i + 1, inet_ntoa(*((struct in_addr *)(ptr))));
				ptr = pHost->h_addr_list[++i];
			}
		}
	}

	else if (mode.compare("recv") == 0) {
		//if (argc == 4) {
		//	if (attr.compare("-stat") == 0) { updateTime = stoi(value); }
		//	else if (attr.compare("-lhost") == 0) { lHost = value; } //remain questionable about the behavior of lHost
		//	else if (attr.compare("-lport") == 0) { lPort = value; }
		//	else if (attr.compare("-proto") == 0) {
		//		transform(value.begin(), value.end(), value.begin(), ::toupper);
		//		protocol = value;
		//	}
		//	else if (attr.compare("-pktsize") == 0) { pktSize = stoi(value); }
		//	else if (attr.compare("-rbufsize") == 0) { bufferSize = stoi(value); }
		//	else {}
		//}
		printf("receiving mode\n");
		printf("refresh_interval=%d\n", updateTime);
		printf("local_host=%s\n", lHost.c_str());
		printf("local_port=%s\n", lPort.c_str());
		printf("protocol=%s\n", protocol.c_str());
		printf("packet_size=%d\n", pktSize);
		printf("buffer_size=%d\n", bufferSize);


		EnterCriticalSection(&CriticalSection);
		context.packetSize = pktSize;
		context.updateTime = updateTime;
		LeaveCriticalSection(&CriticalSection);

		DWORD id = 1;
		HANDLE thread = CreateThread(NULL, 0, RecvThread, NULL, 0, &id);

		char * buffer = (char *)calloc(sizeof(char), pktSize);
		long int receivenum = 0;

		if (protocol.compare("UDP") == 0) {
			sockaddr_in *UDP_Addr = new sockaddr_in;
			memset(UDP_Addr, 0, sizeof(struct sockaddr_in));
			UDP_Addr->sin_family = AF_INET;
			UDP_Addr->sin_port = htons(stoi(lPort));
			UDP_Addr->sin_addr.s_addr = DEFAULT_BIND_NAME;
			SOCKET Sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (Sockfd == INVALID_SOCKET)
			{
				cout << "socket failed with error: " << WSAGetLastError() << endl;
				return -1;
			}
			//bind(Sockfd, (struct sockaddr *)UDP_Addr, sizeof(struct sockaddr_in));
			if (bind(Sockfd, (struct sockaddr *)UDP_Addr, sizeof(struct sockaddr_in)) != 0)
			{
				cout << "bind() failed with error: " << WSAGetLastError() << endl;
				return -1;
			}

			int optVal;
			int optLen = sizeof(int);
			if (getsockopt(Sockfd, SOL_SOCKET, SO_RCVBUF, (char*)&optVal, &optLen) != SOCKET_ERROR)
				printf("original buffer_size: %ld\n", optVal);
			else {
				cout << "get buffer size error: " << WSAGetLastError() << endl;
			}

			if (setsockopt(Sockfd, SOL_SOCKET, SO_RCVBUF, (char *)(&bufferSize), sizeof(bufferSize)) < 0) {
				cout << "set buffer size error: " << WSAGetLastError() << endl;
				return -1;
			}
			else {
				printf("new buffer_size: %d\n", bufferSize);
			}
			int packRec = 0;
			double average = 0;
			double jitter = 0;
			//cout << "binded the socket to the UDP address" << endl;
			//char * buffer = (char *)calloc(sizeof(char), bufferSize);
			while (1)
			{
				DWORD beforeTime = GetTickCount();
				//printf("tt\n");
				sockaddr_in SenderAddr;
				int SenderAddrSize = sizeof(SenderAddr);
				int bytes_recv = 0;
				//printf("bytes_recv: %d\n", bytes_recv);
				while (bytes_recv < pktSize) {
					int retVal = recvfrom(Sockfd, buffer + bytes_recv, pktSize, 0, (SOCKADDR *)&SenderAddr, &SenderAddrSize);
					if ((retVal == SOCKET_ERROR) || (retVal == 0))
					{
						cout << "recv() failed. Error code: " << WSAGetLastError() << endl;
						return -1;
					}
					else if (retVal > 0) {
						bytes_recv += retVal;
					}
				}
				packRec++;
				memcpy(&receivenum, buffer, sizeof(long int));
				//printf("receive numer : %ld\n", receivenum);
				DWORD endTime = GetTickCount();

				EnterCriticalSection(&CriticalSection);
				//printf("send critical section\n");
				context.packaccu = packRec;
				context.packno = receivenum + 1;
				context.packlost = receivenum + 1 - packRec;
				context.currentTime = endTime;//remain questionable at this stage
				average = context.average;
				average = (double)(average *  receivenum + endTime - beforeTime) / (receivenum + 1);
				jitter = context.jitter;
				jitter = (double)(jitter *  receivenum + abs(endTime - beforeTime - average)) / (receivenum + 1);
				context.average = average;
				context.jitter = jitter;
				LeaveCriticalSection(&CriticalSection);
			}
			delete UDP_Addr;
			UDP_Addr = 0;
			closesocket(Sockfd);
			free(buffer);
		}
		else if (protocol.compare("TCP") == 0) {
			sockaddr_in *TCP_Addr = new sockaddr_in;
			memset(TCP_Addr, 0, sizeof(struct sockaddr_in));
			TCP_Addr->sin_family = AF_INET;
			TCP_Addr->sin_port = htons(stoi(lPort));
			TCP_Addr->sin_addr.s_addr = DEFAULT_BIND_NAME;

			SOCKET Sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			bind(Sockfd, (struct sockaddr *)TCP_Addr, sizeof(struct sockaddr_in));
			listen(Sockfd, 5);
			SOCKET newsfd = accept(Sockfd, 0, 0);

			int optVal;
			int optLen = sizeof(int);
			if (getsockopt(Sockfd, SOL_SOCKET, SO_RCVBUF, (char*)&optVal, &optLen) != SOCKET_ERROR)
				printf("original buffer_size: %ld\n", optVal);
			else {
				cout << "get buffer size error: " << WSAGetLastError() << endl;
			}

			if (setsockopt(newsfd, SOL_SOCKET, SO_RCVBUF, (char *)(&bufferSize), sizeof(bufferSize)) < 0) {
				cout << "set buffer size error: " << WSAGetLastError() << endl;
				return -1;
			}
			else {
				printf("new buffer_size: %d\n", bufferSize);
			}
			int packRec = 0;
			double average = 0;
			double jitter = 0;
			//cout << "accepted a new collection" << endl;
			while (1)
			{
				DWORD beforeTime = GetTickCount();
				int bytes_recv = 0;
				while (bytes_recv < pktSize) {
					int retVal = recv(newsfd, buffer + bytes_recv, pktSize, MSG_WAITALL);
					if (retVal > 0) {
						bytes_recv += retVal;
					}
					else {
						cout << "recv() failed. Error code: " << WSAGetLastError() << endl;
						cout << "connection lost.";
						return -1;
					}
				}
				packRec++;
				memcpy(&receivenum, buffer, sizeof(long int));
				//printf("receive numer : %ld\n", receivenum);
				DWORD endTime = GetTickCount();

				EnterCriticalSection(&CriticalSection);
				//printf("send critical section\n");
				context.packaccu = packRec;
				context.packno = receivenum + 1;
				context.packlost = receivenum + 1 - packRec;
				context.currentTime = endTime;//remain questionable at this stage
				average = context.average;
				average = (double)(average *  receivenum + endTime - beforeTime) / (receivenum + 1);
				jitter = context.jitter;
				jitter = (double)(jitter *  receivenum + abs(endTime - beforeTime - average)) / (receivenum + 1);
				context.average = average;
				context.jitter = jitter;
				LeaveCriticalSection(&CriticalSection);
			}
			delete TCP_Addr;
			TCP_Addr = 0;
			closesocket(newsfd);
			closesocket(Sockfd);
			free(buffer);
		}
		else {}
	}
	else if (mode.compare("send") == 0) {

		long int numSent = 0;

		//if (argc == 4) {
		//	if (attr.compare("-stat") == 0) { updateTime = stoi(value); }
		//	else if (attr.compare("-rhost") == 0) { rHost = value; }
		//	else if (attr.compare("-rport") == 0) { rPort = value; }
		//	else if (attr.compare("-proto") == 0) {
		//		transform(value.begin(), value.end(), value.begin(), ::toupper);
		//		protocol = value;
		//	}
		//	else if (attr.compare("-pktsize") == 0) { pktSize = stoi(value); }
		//	else if (attr.compare("-pktrate") == 0) { pktRate = stoi(value); }
		//	else if (attr.compare("-pktnum") == 0) { pktNum = stoi(value); }
		//	else if (attr.compare("-sbufsize") == 0) { bufferSize = stoi(value); }
		//	else {}
		//}
		printf("sending mode\n");
		printf("refresh_interval=%d\n", updateTime);
		printf("remote_host=%s\n", rHost.c_str());
		printf("remote_port=%s\n", rPort.c_str());
		printf("protocol=%s\n", protocol.c_str());
		printf("packet_size=%d\n", pktSize);
		printf("rate=%d\n", pktRate);
		printf("num=%d\n", pktNum);
		printf("buffer_size=%d\n", bufferSize);

		//char buffer[1000];
		//int numSent = 0;
		char * buffer = (char *)calloc(sizeof(char), pktSize);

		//update attributes in the context (sender)
		EnterCriticalSection(&CriticalSection);
		context.packetSize = pktSize;
		context.updateTime = updateTime;
		LeaveCriticalSection(&CriticalSection);

		//create thread
		DWORD id = 1;
		HANDLE thread = CreateThread(NULL, 0, SendThread, NULL, 0, &id);

		if (protocol.compare("UDP") == 0) {
			struct addrinfo aiHints;
			struct addrinfo *aiList = NULL;
			memset(&aiHints, 0, sizeof(aiHints));
			aiHints.ai_family = AF_INET;
			aiHints.ai_socktype = SOCK_DGRAM;
			aiHints.ai_protocol = IPPROTO_UDP;
			memset(buffer, 'a', pktSize);
			if (getaddrinfo(rHost.c_str(), rPort.c_str(), &aiHints, &aiList) != 0)
			{
				cout << "getaddrinfo() failed. Error code: " << WSAGetLastError() << endl;
				return -1;
			}
			SOCKET Sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (Sockfd == INVALID_SOCKET)
			{
				cout << "socket failed with error: " << WSAGetLastError() << endl;
				return -1;
			}

			int optVal;
			int optLen = sizeof(int);
			if (getsockopt(Sockfd, SOL_SOCKET, SO_SNDBUF, (char*)&optVal, &optLen) != SOCKET_ERROR)
				printf("original buffer_size: %ld\n", optVal);
			else {
				cout << "get buffer size error: " << WSAGetLastError() << endl;
			}

			if (setsockopt(Sockfd, SOL_SOCKET, SO_SNDBUF, (char *)(&bufferSize), sizeof(bufferSize)) < 0) {
				cout << "socket set buffer error: " << WSAGetLastError() << endl;
				return -1;
			}
			else {
				printf("new buffer_size: %d\n", bufferSize);
			}

			while (pktNum == 0 || (pktNum != 0 && numSent <= pktNum))
			{
				DWORD beforeTime = GetTickCount();
				memcpy(buffer, &numSent, sizeof(long int));
				int bytes_sent = 0;

				while (bytes_sent < pktSize) {
					int r = sendto(Sockfd, buffer + bytes_sent, pktSize, 0, aiList->ai_addr, sizeof(SOCKADDR));
					if (r > 0) {
						bytes_sent += r;
					}
					else {
						cout << "sendto() failed. Error code: " << WSAGetLastError() << endl;;
						return -1;
					}
				}
				numSent++;
				DWORD endTime = GetTickCount();
				DWORD targetTime = beforeTime + ((double)pktSize / pktRate) * 1000;
				if (endTime < targetTime && pktRate != 0) {
					Sleep(targetTime - endTime);
				}
				DWORD realTime = GetTickCount();
				EnterCriticalSection(&CriticalSection);
				context.packno++;
				context.currentTime = realTime;
				LeaveCriticalSection(&CriticalSection);
			}
			closesocket(Sockfd);
			free(buffer);
		}
		else if (protocol.compare("TCP") == 0) {
			struct addrinfo aiHints;
			struct addrinfo *aiList = NULL;
			memset(buffer, 'a', pktSize);
			memset(&aiHints, 0, sizeof(aiHints));
			aiHints.ai_family = AF_INET;
			aiHints.ai_socktype = SOCK_STREAM;
			aiHints.ai_protocol = IPPROTO_TCP;

			if (getaddrinfo(rHost.c_str(), rPort.c_str(), &aiHints, &aiList) != 0)
			{
				cout << "getaddrinfo() failed. Error code: " << WSAGetLastError() << endl;
				return -1;
			}
			SOCKET Sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (connect(Sockfd, aiList->ai_addr, sizeof(struct sockaddr)) == SOCKET_ERROR)
			{
				cout << "connect() failed. Error code: " << WSAGetLastError() << endl;
				return -1;
			}

			int optVal;
			int optLen = sizeof(int);
			if (getsockopt(Sockfd, SOL_SOCKET, SO_SNDBUF, (char*)&optVal, &optLen) != SOCKET_ERROR)
				printf("original buffer_size: %ld\n", optVal);
			else {
				cout << "get buffer size error: " << WSAGetLastError() << endl;
			}

			if (setsockopt(Sockfd, SOL_SOCKET, SO_SNDBUF, (char *)(&bufferSize), sizeof(bufferSize)) < 0) {
				cout << "socket set buffer error: " << WSAGetLastError() << endl;
				return -1;
			}
			else {
				printf("new buffer_size: %d\n", bufferSize);
			}

			cout << "connect to the server " << rHost << ":" << rPort << endl;
			while (pktNum == 0 || (pktNum != 0 && numSent <= pktNum)) {
				DWORD beforeTime = GetTickCount();
				memcpy(buffer, &numSent, sizeof(long int));
				int bytes_sent = 0;
				while (bytes_sent < pktSize) {
					int r = send(Sockfd, buffer + bytes_sent, pktSize, 0);
					if (r > 0) {
						bytes_sent += r;
					}
					else {
						cout << "sendto() failed. Error code: " << WSAGetLastError() << endl;;
						return -1;
					}
				}
				numSent++;
				DWORD endTime = GetTickCount();
				DWORD targetTime = beforeTime + ((double)pktSize / pktRate) * 1000;
				if (endTime < targetTime && pktRate != 0) {
					Sleep(targetTime - endTime);
				}
				DWORD realTime = GetTickCount();
				EnterCriticalSection(&CriticalSection);
				context.packno++;
				context.currentTime = realTime;
				LeaveCriticalSection(&CriticalSection);
			}
			closesocket(Sockfd);
			free(buffer);
		}
		else {}
	}
	else {}

	WSACleanup();
	return 0;
}
DWORD WINAPI SendThread(LPVOID lpParam) {
	//printf("ongoing");
	int updateTime;
	int packSize;
	clock_t startTime;
	clock_t currentTime;
	double elapse = 0;
	double throughPut;
	long long packNo;
	EnterCriticalSection(&CriticalSection);
	packSize = context.packetSize;
	updateTime = context.updateTime;
	startTime = context.startTime;
	LeaveCriticalSection(&CriticalSection);
	//Sleep(updateTime);
	while (true) {
		Sleep(updateTime);
		EnterCriticalSection(&CriticalSection);
		//printf("thread critical section\n");
		packNo = context.packno;
		currentTime = context.currentTime;
		LeaveCriticalSection(&CriticalSection);
		if (currentTime == 0 || currentTime == startTime) {
			continue; //not yet updated
		}
		else {
			elapse = (double)(currentTime - startTime) / 1000;
		}
		throughPut = packNo*packSize / (elapse * 1000);
		printf("\rElapsed[%ds] Rate[%.5fKbps]", (int)elapse, throughPut);
	}
	return 0;
}

DWORD WINAPI RecvThread(LPVOID lpParam) {
	int updateTime;
	int packSize;
	int numPackrec; //accumulated
	int lostNum; //lost
	double lostRate;
	clock_t startTime;
	clock_t currentTime;
	double elapse;
	double jitter;
	double throughPut;
	long long packNo;
	EnterCriticalSection(&CriticalSection);
	packSize = context.packetSize;
	updateTime = context.updateTime;
	startTime = context.startTime;
	LeaveCriticalSection(&CriticalSection);
	//Sleep(updateTime);
	while (true) {
		Sleep(updateTime);
		EnterCriticalSection(&CriticalSection);
		//printf("thread critical section\n");
		packNo = context.packno;
		currentTime = context.currentTime;
		jitter = context.jitter;
		numPackrec = context.packaccu;
		lostNum = context.packlost;
		LeaveCriticalSection(&CriticalSection);
		if (lostNum == 0) {
			lostRate = 0;
		}
		else { lostRate = (double)lostNum *100 / (double)(lostNum + numPackrec); }
		if (currentTime == 0 || currentTime == startTime) {
			continue;
		}
		else {
			elapse = (double)(currentTime - startTime) / 1000;
			throughPut = packNo*packSize / (elapse * 1000);
		}
		//if (lostNum != 0){
		//	cout << lostRate << endl;
		//}
		printf("\rElapsed[%ds] Pkts[%d] Lost[%d, %.5f%%] Rate[%.5fKbps] Jitter[%.2fms]", (int)elapse, numPackrec, lostNum, lostRate, throughPut, jitter);
	}
	return 0;
}