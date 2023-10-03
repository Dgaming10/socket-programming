#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <iphlpapi.h>

#define HAVE_REMOTE
#include <pcap.h>
#pragma comment(lib, "Ws2_32.lib")

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#define BUFFER_LEN 512
#define MAX_CLIENTS 255
char* base64Decode(const char* decrypted);
char* base64Encode(const char* input);

struct icmpHeader {
	unsigned char type;
	unsigned char code;
	uint16_t checksum;
	uint16_t identifier;
	uint16_t sequenceNumber;
};

unsigned short icmpEchoChecksum(unsigned short* buf, int len) {
	unsigned long sum = 0;

	while (len > 1) {
		sum += *buf++;
		len -= 2;
	}

	if (len == 1) {
		sum += *(unsigned char*)buf;
	}

	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return (unsigned short)(~sum);
}

int strcasecompare(const char* first, const char* second) {
	while (*first != '\0' && *second != '\0') {
		int diff = tolower((unsigned char)*first) - tolower((unsigned char)*second);
		if (diff != 0) {
			return diff;
		}
		first++;
		second++;
	}

	if (*first == '\0' && *second != '\0') {
		return -1;
	}
	else if (*first != '\0' && *second == '\0') {
		return 1;
	}

	return 0;
}

void ping(uint16_t numToPing) {
	struct icmpHeader header;
	header.type = 8;  // ICMP Echo Request
	header.code = 0;
	header.identifier = 29;
	header.sequenceNumber = 0;
	char buffer[] = "TEST";
	header.checksum = 0;
	char icmpPacket[BUFFER_LEN];
	memcpy(icmpPacket, &header, sizeof(header));
	memcpy(icmpPacket + sizeof(header), buffer, strlen(buffer) + 1);
	header.checksum = icmpEchoChecksum((unsigned short*)(icmpPacket), sizeof(header) + strlen(buffer));
	memcpy(icmpPacket, &header, sizeof(header));

	struct sockaddr_in dest_in;
	memset(&dest_in, 0, sizeof(struct sockaddr_in));
	dest_in.sin_family = AF_INET;

	struct addrinfo hints, * result, * ptr;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	while ((getchar()) != '\n');
	printf("Enter domain (max 50 characters): ");
	char inputDomain[50];
	fgets(inputDomain, sizeof(inputDomain), stdin);
	size_t len = strlen(inputDomain);
	if (len > 0 && inputDomain[len - 1] == '\n') {
		inputDomain[len - 1] = '\0';
	}
	else {
		int c;
		while ((c = getchar()) != '\n' && c != EOF);
	}

	if (getaddrinfo(inputDomain, NULL, &hints, &result) != 0) {
		perror("getaddrinfo");
		return;
	}

	char ans[16];
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		struct sockaddr_in* ip = (struct sockaddr_in*)ptr->ai_addr;
		inet_ntop(AF_INET, &(ip->sin_addr), ans, sizeof(ans));
		printf("IP: %s\n", ans);
		dest_in.sin_addr = ip->sin_addr;
		break;
	}

	freeaddrinfo(result);

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == -1) {
		perror("socket");
		return;
	}

	for (int i = 0; i < numToPing; i++) {
		sendto(sock, icmpPacket, sizeof(header) + strlen(buffer) + 1, 0, (struct sockaddr*)&dest_in, sizeof(dest_in));
		socklen_t len = sizeof(dest_in);
		char p[BUFFER_LEN];
		int m = recvfrom(sock, p, sizeof(p), 0, (struct sockaddr*)&dest_in, &len);

		printf("RECEIVED %d bytes\n", m);
	}

	closesocket(sock);
}

void listenFunction(unsigned short portNum) {

	if (portNum < 1024) {
		perror("Port is reserved or negative.");
		return;
	}

	SOCKET serverSock = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSock == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		return;
	}

	struct sockaddr_in serverADDR;
	ZeroMemory(&serverADDR, sizeof(serverADDR));
	serverADDR.sin_family = AF_INET;
	serverADDR.sin_addr.s_addr = htonl(INADDR_ANY);
	serverADDR.sin_port = htons(portNum);

	if (bind(serverSock, (struct sockaddr*)&serverADDR, sizeof(serverADDR)) == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		closesocket(serverSock);
		return;
	}

	if (listen(serverSock, SOMAXCONN) == SOCKET_ERROR) {
		printf("Listen failed with error: %ld\n", WSAGetLastError());
		closesocket(serverSock);
		return;
	}

	printf("Server is listening on port %d...\n", portNum);

	struct sockaddr_in clientADDR;
	int clientADDRLen = sizeof(clientADDR);
	SOCKET clientSock = accept(serverSock, (struct sockaddr*)&clientADDR, &clientADDRLen);
	if (clientSock == INVALID_SOCKET) {
		printf("accept failed: %d\n", WSAGetLastError());
		closesocket(serverSock);
		return;
	}

	char finalIP[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &clientADDR.sin_addr, finalIP, sizeof(finalIP));
	printf("Accepted connection from %s:%d\n", finalIP, ntohs(clientADDR.sin_port));

	closesocket(clientSock);
	closesocket(serverSock);

}

void scanForOpenTCPPorts(char* ip, uint16_t startPort, uint16_t endPort, uint16_t timeout) {

	int sockFD;
	struct sockaddr_in serverADDR;
	fd_set fdset;
	struct timeval tv;

	ZeroMemory(&serverADDR, sizeof(serverADDR));
	serverADDR.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &serverADDR.sin_addr);

	u_long mode = 1;
	sockFD = socket(AF_INET, SOCK_STREAM, 0);
	ioctlsocket(sockFD, FIONBIO, &mode);

	for (int i = startPort; i <= endPort; ++i) {
		printf("Currently trying on port: %d\n", i);
		serverADDR.sin_port = htons(i);
		int connectResult = connect(sockFD, (struct sockaddr*)&serverADDR, sizeof(serverADDR));

		if (connectResult == 0) {
			printf("Port is active\n");
		}
		else {
			int error = WSAGetLastError();
			if (error == WSAEWOULDBLOCK) {
				FD_ZERO(&fdset);
				FD_SET(sockFD, &fdset);
				tv.tv_sec = timeout;
				tv.tv_usec = 0;

				int selectResult = select(0, NULL, &fdset, NULL, &tv);

				if (selectResult == 0) {
					printf("Connection timed out\n");
				}
				else if (selectResult > 0) {
					int optval;
					int optlen = sizeof(optval);
					getsockopt(sockFD, SOL_SOCKET, SO_ERROR, (char*)&optval, &optlen);
					if (optval == 0) {
						printf("Port is active\n");
					}
					else {
						printf("Error in connecting: %d\n", optval);
					}
				}
				else {
					printf("Error in select\n");
				}
			}
			else {
				printf("Error in connecting: %d\n", error);
			}
		}

		closesocket(sockFD);
		sockFD = socket(AF_INET, SOCK_STREAM, 0); 
		ioctlsocket(sockFD, FIONBIO, &mode);

	}

}

char* sendHTTPGetRequest(const char* host, const char* path, uint16_t timeoutSec)
{
	struct addrinfo hints, * serverInfo;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, "http", &hints, &serverInfo) != 0) {
		printf("Failed to resolve hostname.\n");
		return NULL;
	}

	SOCKET sock = socket(serverInfo->ai_family, serverInfo->ai_socktype, serverInfo->ai_protocol);

	if (connect(sock, serverInfo->ai_addr, (int)serverInfo->ai_addrlen) < 0) {
		printf("Failed to connect to the server.\n");
		freeaddrinfo(serverInfo);
		closesocket(sock);
		WSACleanup();
		return NULL;
	}

	freeaddrinfo(serverInfo);

	char request[BUFFER_LEN];
	snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host);
	send(sock, request, strlen(request), 0);

	char buffer[BUFFER_LEN];
	int totalBytesReceived = 0;
	char* response = NULL;
	int responseSize = 0;

	while (1) {
		fd_set readSet;
		FD_ZERO(&readSet);
		FD_SET(sock, &readSet);

		struct timeval timeout;
		timeout.tv_sec = timeoutSec;
		timeout.tv_usec = 0;

		int selectResult = select(0, &readSet, NULL, NULL, &timeout);
		if (selectResult == SOCKET_ERROR) {
			printf("Select error.\n");
			break;
		}
		else if (selectResult == 0) {
			printf("Timeout reached. Closing the connection.\n");
			break;
		}

		int bytesRead = recv(sock, buffer, BUFFER_LEN, 0);
		if (bytesRead <= 0) {
			break;
		}

		if (totalBytesReceived + bytesRead > responseSize) {
			responseSize = totalBytesReceived + bytesRead + 1;
			char* newResponse = realloc(response, responseSize);
			if (!newResponse) {
				printf("Memory allocation failed.\n");
				free(response);
				closesocket(sock);
				WSACleanup();
				return NULL;
			}
			response = newResponse;
		}

		memcpy(response + totalBytesReceived, buffer, bytesRead);
		totalBytesReceived += bytesRead;
		response[totalBytesReceived] = '\0';
	}

	closesocket(sock);
	WSACleanup();

	if (totalBytesReceived <= 0) {
		printf("No data received or an error occurred.\n");
		free(response);
		return NULL;
	}

	return response;
}

void openTCPServer(uint16_t portNum) {

	char ackBuff[BUFFER_LEN];
	fd_set readFDS;
	SOCKET clientSockets[MAX_CLIENTS] = { 0 };
	struct sockaddr_in sockInfo;
	SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (listenSocket == INVALID_SOCKET) {
		fprintf(stderr, "Failed to create socket: %d\n", WSAGetLastError());
		WSACleanup();
		return;
	}

	const int p = 1;
	setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&p, sizeof(int));

	ZeroMemory(&sockInfo, sizeof(sockInfo));
	sockInfo.sin_family = AF_INET;
	sockInfo.sin_port = htons(portNum);
	sockInfo.sin_addr.s_addr = INADDR_ANY;

	if (bind(listenSocket, (struct sockaddr*)&sockInfo, sizeof(sockInfo)) == SOCKET_ERROR) {
		fprintf(stderr, "Bind failed: %d\n", WSAGetLastError());
		return;
	}

	if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
		fprintf(stderr, "Listen failed: %d\n", WSAGetLastError());
		return;
	}

	SOCKET clientSocket;
	printf("Server is listening on port %d!\n", portNum);
	int maxSocket = listenSocket;

	while (1) {
		FD_ZERO(&readFDS);
		FD_SET(listenSocket, &readFDS);
		for (int i = 0; i < MAX_CLIENTS; i++) {
			SOCKET currentSocket = clientSockets[i];
			if (currentSocket > 0) {
				FD_SET(currentSocket, &readFDS);
				if (currentSocket > maxSocket) {
					maxSocket = currentSocket;
				}
			}
		}

		select(maxSocket + 1, &readFDS, NULL, NULL, NULL);

		if (FD_ISSET(listenSocket, &readFDS)) {
			clientSocket = accept(listenSocket, NULL, NULL);
			printf("New connection accepted from %d\n", clientSocket);

			for (int i = 0; i < MAX_CLIENTS; i++) {
				if (clientSockets[i] == 0) {
					clientSockets[i] = clientSocket;
					break;
				}
			}
		}

		for (int i = 0; i < MAX_CLIENTS; i++) {
			SOCKET currentSocket = clientSockets[i];
			if (currentSocket > 0 && FD_ISSET(currentSocket, &readFDS)) {
				char buffer[BUFFER_LEN];
				int m = recv(currentSocket, buffer, sizeof(buffer) - 1, 0);
				if (m == SOCKET_ERROR) {
					fprintf(stderr, "Receive error on client %d: %d\n", currentSocket, WSAGetLastError());
					closesocket(currentSocket);
					clientSockets[i] = INVALID_SOCKET;
					FD_CLR(currentSocket, &readFDS);
					continue;
				}
				else if (strcasecompare(buffer,"exit") == 0) {
					printf("Connection closed by client %d\n", currentSocket);
					closesocket(currentSocket);
					clientSockets[i] = 0;
					FD_CLR(currentSocket, &readFDS);
					continue;
				}
				buffer[m] = '\0';

				char* encodedMSG = base64Decode(buffer);
				printf("Received from client %d: %s\nreply:", currentSocket, encodedMSG);
				free(encodedMSG);

				printf("Enter your reply: ");
				scanf_s(" %[^\n]%*c", ackBuff, BUFFER_LEN);
				char* encodedREPLY = base64Encode(ackBuff);
				send(currentSocket, encodedREPLY, strlen(encodedREPLY), 0);
				free(encodedREPLY); 
			}
		}
	}

}

void connectToTCPServer(char* portIP, uint16_t portNum) {

	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		fprintf(stderr, "Failed to create socket: %d\n", WSAGetLastError());
		WSACleanup();
		return;
	}

	struct sockaddr_in serverADDR;
	ZeroMemory(&serverADDR, sizeof(serverADDR));
	serverADDR.sin_family = AF_INET;
	serverADDR.sin_port = htons(portNum);

	if (inet_pton(AF_INET, portIP, &serverADDR.sin_addr) <= 0) {
		fprintf(stderr, "Invalid IP address: %s\n", portIP);
		return;
	}

	if (connect(sock, (struct sockaddr*)&serverADDR, sizeof(serverADDR)) == SOCKET_ERROR) {
		fprintf(stderr, "Connection failed: %d\n", WSAGetLastError());
		return;
	}

	char buffer[BUFFER_LEN];
	char receiverBuff[BUFFER_LEN];
	while (1) {
		printf("Enter a message (type 'exit' to quit): ");
		scanf_s(" %[^\n]%*c", buffer, BUFFER_LEN);

		char* encoded = base64Encode(buffer);
		int m = send(sock, encoded, strlen(encoded) + 1, 0);
		free(encoded); 
		if (m == SOCKET_ERROR) {
			fprintf(stderr, "Send failed: %d\n", WSAGetLastError());
			break;
		}

		printf("Sent %d bytes!\n", m);

		int n = recv(sock, receiverBuff, BUFFER_LEN, 0);
		if (n == SOCKET_ERROR || strcasecompare(receiverBuff,"exit") == 0) {
			fprintf(stderr, "Receive failed: %d\n", WSAGetLastError());
			break;
		}

		if (n == 0) {
			printf("Server closed the connection\n");
			break;
		}

		receiverBuff[n] = '\0';
		char* decoded = base64Decode(receiverBuff);
		printf("Received reply from the server: %s\n", decoded);
		free(decoded); 
	}

}


void receiveFile(const char* source, uint16_t portNum) {
	FILE* filePointer = NULL;
	char buff[BUFFER_LEN];
	char fileFullName[50];
	SOCKET receiverSocket = INVALID_SOCKET;

	receiverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (receiverSocket == INVALID_SOCKET) {
		printf("Failed to create socket.\n");
		WSACleanup();
		return;
	}

	struct sockaddr_in myInfo;
	myInfo.sin_family = AF_INET;
	myInfo.sin_port = htons(portNum);
	inet_pton(AF_INET, source, &myInfo.sin_addr);

	if (connect(receiverSocket, (struct sockaddr*)&myInfo, sizeof(myInfo)) == SOCKET_ERROR) {
		printf("Failed to connect to the server.\n");
		closesocket(receiverSocket);
		WSACleanup();
		return;
	}

	if (recv(receiverSocket, fileFullName, sizeof(fileFullName), 0) == SOCKET_ERROR) {
		printf("Failed to receive the file name.\n");
		closesocket(receiverSocket);
		WSACleanup();
		return;
	}

	if (recv(receiverSocket, buff, sizeof(buff), 0) == SOCKET_ERROR) {
		printf("Failed to receive the file content.\n");
		closesocket(receiverSocket);
		WSACleanup();
		return;
	}

	printf("Received file name: %s\n", fileFullName);

	if (fopen_s(&filePointer, fileFullName, "wb") != 0) {
		printf("Failed to open the output file.\n");
		closesocket(receiverSocket);
		WSACleanup();
		return;
	}

	size_t bytesWritten = fprintf(filePointer, "%s", buff);
	fclose(filePointer);

	if (bytesWritten != strlen(buff)) {
		printf("Failed to write the complete file content.\n");
		closesocket(receiverSocket);
		WSACleanup();
		return;
	}

	printf("File received and written as %s\n", fileFullName);
	closesocket(receiverSocket);
}

char* getFileName(const char* path) {
	const char* lastSlash = strrchr(path, '/');

	if (lastSlash == NULL) {
		return _strdup(path);
	}
	lastSlash++;

	return _strdup(lastSlash);
}

void sendFile(const char* dest, const char* pathToFile, uint16_t portNum) {
	SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocket == INVALID_SOCKET) {
		perror("socket creation failed");
		WSACleanup();
		return;
	}

	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(portNum);
	serverAddr.sin_addr.s_addr = INADDR_ANY;

	if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
		perror("bind failed");
		closesocket(serverSocket);
		WSACleanup();
		return;
	}

	if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
		perror("listen failed");
		closesocket(serverSocket);
		WSACleanup();
		return;
	}

	struct sockaddr_in clientAddr;
	int clientAddrSize = sizeof(clientAddr);
	SOCKET clientSocket;

	while (1) {
		clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
		if (clientSocket == INVALID_SOCKET) {
			perror("accept failed");
			closesocket(serverSocket);
			WSACleanup();
			return;
		}

		char clientIP[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, sizeof(clientIP)) == NULL) {
			perror("inet_ntop failed");
			closesocket(clientSocket);
			closesocket(serverSocket);
			WSACleanup();
			return;
		}

		printf("Connected to IP: %s\n", clientIP);

		if (strcmp(clientIP, dest) != 0) {
			printf("You are not the right client! Goodbye!\n");
			closesocket(clientSocket);
		}
		else {
			break;
		}
	}
	FILE* fileP = (FILE*)malloc(sizeof(FILE));
	fopen_s(&fileP, pathToFile, "r");
	if (fileP == NULL) {
		perror("File not found");
		closesocket(clientSocket);
		closesocket(serverSocket);
		WSACleanup();
		return;
	}

	char fileBUFFER[513];
	int bytesRead;

	char c;
	int i = 0;
	while (fscanf_s(fileP, "%c", &c, 1) == 1 && c != EOF && i < 512)
	{
		fileBUFFER[i++] = c;
	}
	fileBUFFER[i] = '\0';
	char* fileFULLNAME = getFileName(pathToFile);
	send(clientSocket, fileFULLNAME, strlen(fileFULLNAME) + 1, 0);
	send(clientSocket, fileBUFFER, strlen(fileBUFFER) + 1, 0);

	fclose(fileP);
	closesocket(clientSocket);
	closesocket(serverSocket);
}


void getMacAddr(const char* destIPStr) {
	ULONG mac[2];
	struct in_addr destIP;

	if (inet_pton(AF_INET, destIPStr, &destIP) != 1) {
		printf("Invalid IP address format.\n");
		return;
	}

	ULONG length = 6;
	DWORD m = SendARP((IPAddr)destIP.S_un.S_addr, 0, mac, &length);

	if (m == NO_ERROR) {
		printf("ARP request sent successfully.\n");
		printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			(mac[0] & 0xFF), (mac[0] >> 8) & 0xFF, (mac[0] >> 16) & 0xFF, (mac[0] >> 24) & 0xFF,
			(mac[1] & 0xFF), (mac[1] >> 8) & 0xFF);
	}
	else {
		printf("ARP request failed with error code: %d\n", m);
	}
}

char* base64Encode(const char* input) {
	const char base64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	size_t inputLength = strlen(input);
	size_t encodedLength = ((inputLength + 2) / 3) * 4;

	char* encoded = (char*)malloc(encodedLength + 1);
	if (encoded == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
		exit(EXIT_FAILURE);
	}

	size_t i = 0;
	size_t j = 0;

	while (i < inputLength) {
		unsigned char byte1 = input[i++];
		unsigned char byte2 = (i < inputLength) ? input[i++] : 0;
		unsigned char byte3 = (i < inputLength) ? input[i++] : 0;

		unsigned char char1 = byte1 >> 2;
		unsigned char char2 = ((byte1 & 0x03) << 4) | (byte2 >> 4);
		unsigned char char3 = ((byte2 & 0x0F) << 2) | (byte3 >> 6);
		unsigned char char4 = byte3 & 0x3F;

		encoded[j++] = base64Chars[char1];
		encoded[j++] = base64Chars[char2];
		encoded[j++] = (i > inputLength + 1) ? '=' : base64Chars[char3];
		encoded[j++] = (i > inputLength) ? '=' : base64Chars[char4];
	}

	encoded[encodedLength] = '\0';

	return encoded;
}

char* base64Decode(const char* decrypted) {
	const char base64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	size_t inputLength = strlen(decrypted);
	size_t decodedLength = (inputLength * 3) / 4;

	if (inputLength >= 2 && decrypted[inputLength - 2] == '=' && decrypted[inputLength - 1] == '=') {
		decodedLength -= 2;
	}
	else if (inputLength >= 1 && decrypted[inputLength - 1] == '=') {
		decodedLength -= 1;
	}

	char* encoded = (char*)malloc(decodedLength + 1);
	if (encoded == NULL) {
		return NULL;
	}

	size_t i = 0;
	size_t j = 0;

	while (i < inputLength) {
		unsigned char char1, char2, char3, char4;
		unsigned char byte1, byte2, byte3;

		char1 = (strchr(base64Chars, decrypted[i++]) - base64Chars);
		char2 = (strchr(base64Chars, decrypted[i++]) - base64Chars);
		char3 = (strchr(base64Chars, decrypted[i++]) - base64Chars);
		char4 = (strchr(base64Chars, decrypted[i++]) - base64Chars);

		byte1 = (char1 << 2) | (char2 >> 4);
		byte2 = (char2 << 4) | (char3 >> 2);
		byte3 = (char3 << 6) | char4;

		encoded[j++] = byte1;
		if (char3 != '=') {
			encoded[j++] = byte2;
		}
		if (char4 != '=') {
			encoded[j++] = byte3;
		}
	}

	encoded[decodedLength] = '\0';
	return encoded;
}

void sniffLocalPackets() {
	pcap_if_t* alldevs;
	pcap_if_t* current;
	pcap_t* handle;
	char err[PCAP_ERRBUF_SIZE];
	pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, err);
	uint8_t index = 0;
	printf("Choose the sniffed device:\n");
	uint8_t interfaceNum = 0;

	for (current = alldevs; current != NULL; current = current->next) {
		printf("interface number %hhu: %s ------- %s\n", interfaceNum++, current->name, current->description);
	}

	scanf_s("%hhu", &index, sizeof(index));

	for (uint8_t k = 0; k < index && alldevs != NULL; alldevs = alldevs->next, ++k);
	if (alldevs == NULL) {
		printf("Invalid interface selection.\n");
		return;
	}

	printf("You chose: %s ------ %s\n", alldevs->name, alldevs->description);

	handle = pcap_open_live(alldevs->name, 65536, 1, 1000, err);
	if (handle == NULL) {
		printf("Error opening network interface: %s\n", err);
		pcap_freealldevs(alldevs);
		return;
	}

	struct pcap_pkthdr header;
	const u_char* packet;
	uint8_t MAC[6];
	uint8_t IP[16];
	char type[5] = "ipv";
	uint8_t headerLen = 0;
	uint64_t i = 0;

	for (;;) {
		packet = pcap_next(handle, &header);
		if (packet == NULL) {
			continue;
		}

		memcpy(MAC, packet, 6);
		printf("Packet number %lld -> %d bytes captured\n", ++i, header.len);
		printf("Destination MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);

		memcpy(MAC, packet + 6, 6);
		printf("Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);

		if (packet[13] == 0) {
			memcpy(IP, packet + 26, 4);
			type[3] = '4';
			printf("Source IPv4: %d.%d.%d.%d\n", IP[0], IP[1], IP[2], IP[3]);
			memcpy(IP, packet + 30, 4);
			printf("Destination IPv4: %d.%d.%d.%d\n", IP[0], IP[1], IP[2], IP[3]);
			headerLen = 20;
		}
		else {
			memcpy(IP, packet + 22, 16);
			type[3] = '6';
			printf("Source IPv6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				IP[0], IP[1], IP[2], IP[3], IP[4], IP[5], IP[6], IP[7],
				IP[8], IP[9], IP[10], IP[11], IP[12], IP[13], IP[14], IP[15]);
			memcpy(IP, packet + 38, 16);
			printf("Destination IPv6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				IP[0], IP[1], IP[2], IP[3], IP[4], IP[5], IP[6], IP[7],
				IP[8], IP[9], IP[10], IP[11], IP[12], IP[13], IP[14], IP[15]);
			headerLen = 40;
		}
		type[4] = '\0';
		printf("Type -> %s\n", type);
	}

	pcap_close(handle);
	pcap_freealldevs(alldevs);
}

int main(void)
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup failed.\n");
		return 1;
	}


	uint8_t option;
	printf("Choose an option:\n");
	printf("1. Ping\n");
	printf("2. Listen\n");
	printf("3. Scan for open TCP ports\n");
	printf("4. Send HTTP GET request\n");
	printf("5. Open TCP server\n");
	printf("6. Connect to TCP server\n");
	printf("7. Receive file\n");
	printf("8. Send file\n");
	printf("9. Get MAC address\n");
	printf("10. Sniff local packets\n");
	scanf_s("%hhu", &option);

	switch (option) {
	case 1: {
		uint16_t numToPing;
		printf("Enter the number of ICMP packets to send: ");
		scanf_s("%hu", &numToPing);
		ping(numToPing);
		break;
	}
	case 2: {
		uint16_t portNum;
		printf("Enter the port number to listen on: ");
		scanf_s("%hu", &portNum);
		listenFunction(portNum);
		break;
	}
	case 3: {
		char ip[16];
		uint16_t startPort, endPort, timeout;
		printf("Enter the target IP address: ");
		scanf_s(" %15s", ip, sizeof(ip));
		printf("Enter the starting port number: ");
		scanf_s("%hu", &startPort);
		printf("Enter the ending port number: ");
		scanf_s(" %hu", &endPort);
		printf("Enter the timeout (seconds): ");
		scanf_s(" %hu", &timeout);
		scanForOpenTCPPorts(ip, startPort, endPort, timeout);
		break;
	}
	case 4: {
		char host[256], path[256];
		uint16_t timeoutSec;
		printf("Enter the host (e.g., www.example.com): ");
		scanf_s(" %255s", host, sizeof(host));
		printf("Enter the path (e.g., /index.html): ");
		scanf_s(" %255s", path, sizeof(path));
		printf("Enter the timeout (seconds): ");
		scanf_s(" %hu", &timeoutSec);
		char* response = sendHTTPGetRequest(host, path, timeoutSec);
		if (response != NULL) {
			printf("Received HTTP response:\n%s\n", response);
			free(response);
		}
		break;
	}
	case 5: {
		uint16_t portNum;
		printf("Enter the port number to open: ");
		scanf_s("%hu", &portNum);
		openTCPServer(portNum);
		break;
	}
	case 6: {
		char portIP[16];
		uint16_t portNum;
		printf("Enter the server IP address: ");
		scanf_s(" %15s", portIP, sizeof(portIP));
		printf("Enter the server port number: ");
		scanf_s(" %hu", &portNum);
		connectToTCPServer(portIP, portNum);
		break;
	}
	case 7: {
		char source[16];
		uint16_t portNum;
		printf("Enter the source IP address: ");
		scanf_s(" %15s", source, sizeof(source));
		printf("Enter the port number to listen on: ");
		scanf_s(" %hu", &portNum);
		receiveFile(source, portNum);
		break;
	}
	case 8: {
		char dest[16], path[256];
		uint16_t portNum;
		printf("Enter the destination IP address: ");
		scanf_s(" %15s", dest, sizeof(dest));
		printf("Enter the path to the file to send: ");
		scanf_s(" %255s", path, sizeof(path));
		printf("Enter the port number to send on: ");
		scanf_s(" %hu", &portNum);
		sendFile(dest, path, portNum);
		break;
	}
	case 9: {
		char targetIP[16];
		printf("Enter the target IP address: ");
		scanf_s(" %15s", targetIP, sizeof(targetIP));
		getMacAddr(targetIP);
		break;
	}
	case 10: {
		sniffLocalPackets();
		break;
	}
	default:
		printf("Invalid option\n");
		break;
	}

	
	WSACleanup();
	printf("Server is shutting down...\n");

	
	return 0;
}
