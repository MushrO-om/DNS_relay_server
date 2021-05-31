#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "head.h"
#include "initProgram.h"
#include "receiveFromLocal.h"
#include "receiveFromOut.h"

#pragma comment(lib, "Ws2_32.lib")


void outPutCurrentTime()
{
	time_t t;
	struct tm* lt;   
	time(&t);//��ȡʱ�����    
	lt = localtime(&t);//תΪʱ��ṹ��    
	printf("%d/%d/%d %d:%d:%d", lt->tm_year + 1900, lt->tm_mon+1, lt->tm_mday,lt->tm_hour, lt->tm_min, lt->tm_sec);//������
}

//����Ϊ6github3com0��urlתΪgithub.com��ʽ��requestURL
void convertToURL(char* url, char* requestURL)
{
	int i = 0, j = 0, k = 0, len = strlen(url);
	while (i < len)
	{
		if (url[i] > 0 && url[i] <= 63) //���url������(0,64)֮��
		{
			for (j = url[i], i++; j > 0; j--, i++, k++) //���Ƹ�url
				requestURL[k] = url[i];
		}
		if (url[i] != 0) //����Ƿ����������β�Ƿ�Ϊ0
		{
			requestURL[k] = '.';
			k++;
		}
	}
	requestURL[k] = '\0'; 
}


int main(int argc, char* argv[]) {
	listTitle();
	//��ȡ�����в���
	readParameters(argc, argv);
	//��ȡIP-�������ձ�
	readIPURLReflectTable();

	//��ʼ��Win Socket����
	WSAStartup(MAKEWORD(2, 2), &WsaData);
	
	//�������غ��ⲿ��Socket
	localSocket = socket(AF_INET, SOCK_DGRAM, 0);
	outSocket = socket(AF_INET, SOCK_DGRAM, 0);

	
	//��Socket�ӿڸ�Ϊ������ģʽ
	int nonBlock = 1;
	ioctlsocket(outSocket, FIONBIO, (u_long FAR*) & nonBlock);
	ioctlsocket(localSocket, FIONBIO, (u_long FAR*) & nonBlock);
	
	localName.sin_family = AF_INET;//Address family AF_INET����TCP / IPЭ����
	localName.sin_addr.s_addr = INADDR_ANY;    //���ñ��ص�ַΪ����IP��ַ
	localName.sin_port = htons(53); //����DNS�ӿ�Ϊ53

	externName.sin_family = AF_INET; //Address family AF_INET����TCP / IPЭ����
	externName.sin_addr.s_addr = inet_addr(outDNSServerIP);   //�����ⲿDNS������IP��ַ
	externName.sin_port = htons(53);  //����DNS�ӿ�Ϊ53

	//�����׽��ֵ�ѡ��,������ֱ��ض˿ڱ�ռ�����
	int reuse = 1;
	setsockopt(localSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)& reuse, sizeof(reuse));

	//�󶨸��׽��ֵ�53�˿�
	if (bind(localSocket, (struct sockaddr*) & localName, sizeof(localName)) < 0)
	{
		if (debugLevel >= 1)
			printf("Bind socket port failed.\n");
		exit(1);
	}
	//��ʼ��ID���ձ�
	initTransferTable();

	for (;;)
	{
		receiveFromLocal();
		receiveFromOut();
	}
}