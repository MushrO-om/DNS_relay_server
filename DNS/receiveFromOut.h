#pragma once
#include "head.h"

void receiveFromOut()
{
	char buffer[MAX_BUF_SIZE], requestURL[MAX_URL_LENGTH];
	//��BUF����
	for (int i = 0; i < MAX_BUF_SIZE; i++)
		buffer[i] = 0;
	int bufferLength = -1;
	bufferLength = recvfrom(outSocket, buffer, sizeof(buffer), 0, (struct sockaddr*) & out, &lengthClient); //���ⲿ����DNS���ݰ�
	if (bufferLength > -1)//�������DNS���ݰ�
	{
		unsigned short* newID = (unsigned short*)malloc(sizeof(unsigned short));
		memcpy(newID, buffer, sizeof(unsigned short));//��ȡ���ݰ�ͷ����ID����ת�����ID
		int index = (*newID) - 1;//��ת�����IDת��ΪIDת�����������������
		free(newID);//�ͷſռ�
		memcpy(buffer, &oldIDtable[index], sizeof(unsigned short));//ʹ�þ�ID�滻ת�����ID
		isDone[index] = TRUE;//�������󣬽�isDone���ж�Ӧ��������Ϊtrue
		client = IDClient[index];//��ȡ�ͻ��˷�����
		bufferLength = sendto(localSocket, buffer, bufferLength, 0, (SOCKADDR*)& client, sizeof(client));
		int QDCount = ntohs(*((unsigned short*)(buffer + 4))), ANCount = ntohs(*((unsigned short*)(buffer + 6)));
		char* bufferLocation = buffer + 12;//����DNS��ͷ��ָ��
		char ip[16];
		int ipPart1, ipPart2, ipPart3, ipPart4;
		for (int i = 0; i < QDCount; i++)
		{
			convertToURL(bufferLocation, requestURL);
			while (*bufferLocation > 0)//��ȡ��ʶ��ǰ�ļ����������url
				bufferLocation += (*bufferLocation) + 1;
			bufferLocation += 5; //����url�����Ϣ��ָ����һ������
			for (int i = 0; i < ANCount; ++i)
			{
				if ((unsigned char)* bufferLocation == 0xc0) //����Ƿ�Ϊָ��
					bufferLocation += 2;
				else
				{
					while (*bufferLocation > 0)
						bufferLocation += (*bufferLocation) + 1;
					++bufferLocation;//ָ��url���������
				}
				unsigned short responseType = ntohs(*(unsigned short*)bufferLocation);  //�ظ�����
				bufferLocation += 2;
				unsigned short responseClass = ntohs(*(unsigned short*)bufferLocation); //�ظ���
				bufferLocation += 2;
				unsigned short responseHighTTL = ntohs(*(unsigned short*)bufferLocation);//����ʱ���λ
				bufferLocation += 2;
				unsigned short responseLowTTL = ntohs(*(unsigned short*)bufferLocation); //����ʱ���λ
				bufferLocation += 2;
				int TTL = (((int)responseHighTTL) << 16) | responseLowTTL;    //��ϳ�����ʱ��
				int dataLength = ntohs(*(unsigned short*)bufferLocation);   //���ݳ���
				bufferLocation += 2;

				if (responseType == 1) //�����A����
				{
					ipPart1 = (unsigned char)* bufferLocation++;
					ipPart2 = (unsigned char)* bufferLocation++;
					ipPart3 = (unsigned char)* bufferLocation++;
					ipPart4 = (unsigned char)* bufferLocation++;

					sprintf(ip, "%d.%d.%d.%d", ipPart1, ipPart2, ipPart3, ipPart4);//�� ipPart1, ipPart2, ipPart3, ipPart4ƴ��ΪIP��ַ
				}

				//��URL��IP��ŵ�Cache��
				strcpy(URLCache[CacheCount], requestURL);
				strcpy(IPCache[CacheCount], ip);
				CacheCount++;
				//���cache���Ѵ��������cache�����λ��ʼ�滻
				if (CacheCount == MAX_CACHE_LENGTH)
					CacheCount = 0;
				TotalCacheNumber++;
				if (TotalCacheNumber > MAX_CACHE_LENGTH)
					TotalCacheNumber = MAX_CACHE_LENGTH;
				if (debugLevel >= 1)
				{
					cout << Number << ":  ";
					outPutCurrentTime();
					cout << "  " << "Client" << "  " << "127.0.0.1" << "     " << "1.0.0.127.in-addr.arpa, TYPE 12 ,CLASS 1" << endl;
					Number++;
					cout << Number << ":  ";
					outPutCurrentTime();
					cout << "  " << "Client" << "  " << "127.0.0.1" << "     " << requestURL << endl;
					IPV4 = false;
					Number++;
					char outBuffer[2];
					if (debugLevel >= 2) {
						cout << "----------------------------------------" << endl;
						cout << "Type :  " << responseType << "  Class :  " << responseClass << "  TTL :  " << TTL << "  dataLength :  " << dataLength << endl;
						cout << "buffer :  ";
						for (int i = 0; i < bufferLength; i++) {
							_itoa((unsigned short)buffer[i], outBuffer, 16);
							cout << outBuffer[0] << outBuffer[1] << " ";
						}
						cout << endl;
						cout << "----------------------------------------" << endl;
					}
				}


			}
		}
	}

}
