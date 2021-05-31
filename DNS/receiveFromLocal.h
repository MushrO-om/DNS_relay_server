#pragma once
#include "head.h"

void receiveFromLocal()
{
	char buffer[MAX_BUF_SIZE], url[MAX_URL_LENGTH];
	//��BUF����
	for (int i = 0; i < MAX_BUF_SIZE; i++)
		buffer[i] = 0;
	int bufferLength = -1;
	char currentIP[MAX_IP_LENGTH];
	bufferLength = recvfrom(localSocket, buffer, sizeof buffer, 0, (struct sockaddr*) & client, &lengthClient);
	//����ѯ������
	char requestURL[MAX_URL_LENGTH];

	if (bufferLength > 0) {
		//��buffer�е��������ִ���url��
		memcpy(url, &(buffer[12]), bufferLength);
		convertToURL(url, requestURL);

		//��Cache�в�ѯ������
		for (CurrentCacheNumber = 0; CurrentCacheNumber < TotalCacheNumber; CurrentCacheNumber++)
		{
			if (strcmp(requestURL, URLCache[CurrentCacheNumber]) == 0)
				break;
		}
		//���δ��Cache���ҵ�������
		if (CurrentCacheNumber == TotalCacheNumber)
		{
			//��IP-URL���ձ��в��Ҹ�����
			for (CurrentTableNumber = 0; CurrentTableNumber < TotalTableNumber; CurrentTableNumber++) {
				if (strcmp(requestURL, URLTable[CurrentTableNumber]) == 0)
					break;
			}
			//δ����IP-URL���ձ��в鵽
			if (CurrentTableNumber == TotalTableNumber)
			{
				//���ⲿDNS�����������ѯ������
				for (CurrentIDNumber = 0; CurrentIDNumber < MAX_ID_TARNSFER_TABLE_LENGTH; CurrentIDNumber++)
					if (isDone[CurrentIDNumber] == true)
						break;
				if (CurrentIDNumber == MAX_ID_TARNSFER_TABLE_LENGTH)
				{
					;//����
				}
				else {
					unsigned short* oldID = (unsigned short*)malloc(sizeof(unsigned short));
					memcpy(oldID, buffer, sizeof(unsigned short));
					//��oldID����IDת����
					oldIDtable[CurrentIDNumber] = *oldID;
					//��isDone��Ϊfalse
					isDone[CurrentIDNumber] = false;
					IDClient[CurrentIDNumber] = client;
					CurrentIDNumber += 1;
					memcpy(buffer, &CurrentIDNumber, sizeof(unsigned short));
					bufferLength = sendto(outSocket, buffer, bufferLength, 0, (struct sockaddr*) & externName, sizeof(externName));//���ⲿ���������Ͳ�ѯ����
				}
			}
			else {

				strcpy(currentIP, IPTable[CurrentTableNumber]);
				//��ѯ�������Ƿ��ں�������
				char sendbuf[MAX_BUF_SIZE];
				int currenLength = 0;
				if ((strcmp("0.0.0.0", currentIP)) == 0) {
					//����ں��������򷵻�δ�ܲ�ѯ��������IP��ַ
					memcpy(sendbuf, buffer, bufferLength);
					unsigned short flag = htons(0x8183);
					memcpy(&sendbuf[2], &flag, sizeof(unsigned short)); //�����ײ���־��
					flag = htons(0x0001);	//���ش��������Ϊ1
					memcpy(&sendbuf[6], &flag, sizeof(unsigned short));
				}
				else {
					memcpy(sendbuf, buffer, bufferLength);
					unsigned short flag = htons(0x8180);
					memcpy(&sendbuf[2], &flag, sizeof(unsigned short)); //�����ײ���־��
					flag = htons(0x0001);	//���ش��������Ϊ1
					memcpy(&sendbuf[6], &flag, sizeof(unsigned short));

				}
				char answer[16];
				unsigned short Name = htons(0xc00c);  //��������ָ��
				memcpy(answer, &Name, sizeof(unsigned short));
				currenLength += sizeof(unsigned short);

				unsigned short Type = htons(0x0001);  //����
				memcpy(answer + currenLength, &Type, sizeof(unsigned short));
				currenLength += sizeof(unsigned short);

				unsigned short Class = htons(0x0001);  //��
				memcpy(answer + currenLength, &Class, sizeof(unsigned short));
				currenLength += sizeof(unsigned short);

				unsigned long TTL = htonl(0x7b); //����ʱ��
				memcpy(answer + currenLength, &TTL, sizeof(unsigned long));
				currenLength += sizeof(unsigned long);

				unsigned short IPLength = htons(0x0004);  //IP����
				memcpy(answer + currenLength, &IPLength, sizeof(unsigned short));
				currenLength += sizeof(unsigned short);

				unsigned long IP = (unsigned long)inet_addr(currentIP); //���ַ���ʽIPת��Ϊ16������ʽ��IP
				memcpy(answer + currenLength, &IP, sizeof(unsigned long));
				currenLength += sizeof(unsigned long);
				currenLength += bufferLength;
				memcpy(sendbuf + bufferLength, answer, sizeof(answer));

				bufferLength = sendto(localSocket, sendbuf, currenLength, 0, (SOCKADDR*)& client, sizeof(client)); //�����ķ��ͻؿͻ���
				if (debugLevel >= 1)
				{
					if (IPV4) {
						cout << Number << ":  ";
						outPutCurrentTime();
						cout << "  " << "Client" << "  " << "127.0.0.1" << "     " << "1.0.0.127.in-addr.arpa, TYPE 12 ,CLASS 1" << endl;
						Number++;
						cout << Number << ":* ";
						outPutCurrentTime();
						cout << "  " << "Client" << "  " << "127.0.0.1" << "     " << requestURL << endl;
						IPV4 = false;
						Number++;
					}
					else {
						cout << Number << ":  ";
						outPutCurrentTime();
						cout << "  " << "Client" << "  " << "127.0.0.1" << "     " << requestURL << ",  " << "TYPE  A" << ",  " << "CLASS  1" << endl;
						Number++;


						IPV4 = true;
					}

				}
				char outBuffer[2];
				if (debugLevel >= 2) {
					cout << "----------------------------------------" << endl;
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
		else {
			strcpy(currentIP, IPCache[CurrentCacheNumber]);
			char sendbuf[MAX_BUF_SIZE];
			memcpy(sendbuf, buffer, bufferLength);
			unsigned short flag = htons(0x8180);
			memcpy(&sendbuf[2], &flag, sizeof(unsigned short)); //�����ײ���־λ
			flag = htons(0x0001);	//���ûش����
			memcpy(&sendbuf[6], &flag, sizeof(unsigned short));

			int currentLength = 0;
			char answer[16];
			unsigned short Name = htons(0xc00c); //�����ײ���־λ
			memcpy(answer, &Name, sizeof(unsigned short));
			currentLength += sizeof(unsigned short);

			unsigned short Type = htons(0x0001);  //����
			memcpy(answer + currentLength, &Type, sizeof(unsigned short));
			currentLength += sizeof(unsigned short);

			unsigned short Class = htons(0x0001);  //��
			memcpy(answer + currentLength, &Class, sizeof(unsigned short));
			currentLength += sizeof(unsigned short);

			unsigned long TTL = htonl(0x7b); //����ʱ��
			memcpy(answer + currentLength, &TTL, sizeof(unsigned long));
			currentLength += sizeof(unsigned long);

			unsigned short IPLength = htons(0x0004);  //IP����
			memcpy(answer + currentLength, &IPLength, sizeof(unsigned short));
			currentLength += sizeof(unsigned short);

			unsigned long IP = (unsigned long)inet_addr(currentIP); //��IP���ַ�����ת��Ϊ16����
			memcpy(answer + currentLength, &IP, sizeof(unsigned long));
			currentLength += sizeof(unsigned long);
			currentLength += bufferLength;
			memcpy(sendbuf + bufferLength, answer, sizeof(answer));

			bufferLength = sendto(localSocket, sendbuf, currentLength, 0, (SOCKADDR*)& client, sizeof(client)); //��DNS���ķ��ʹ��ͻ���
			if (debugLevel >= 1)
			{
				if (IPV4) {
					cout << Number << ":  ";
					outPutCurrentTime();
					cout << "  " << "Client" << "  " << "127.0.0.1" << "     " << "1.0.0.127.in-addr.arpa, TYPE 12 ,CLASS 1" << endl;
					Number++;
					cout << Number << ":* ";
					outPutCurrentTime();
					cout << "  " << "Client" << "  " << "127.0.0.1" << "     " << requestURL << endl;
					IPV4 = false;
					Number++;
				}
				else {
					cout << Number << ":  ";
					outPutCurrentTime();
					cout << "  " << "Client" << "  " << "127.0.0.1" << "     " << requestURL << ",  " << "TYPE  A" << ",  " << "CLASS  1" << endl;
					Number++;
					IPV4 = true;
				}

			}

			char outBuffer[2];
			if (debugLevel >= 2) {
				cout << "----------------------------------------" << endl;
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