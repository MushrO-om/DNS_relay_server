#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include<cstdio>
#include<cstring>
#include <time.h>
#include<iostream>
#include <WinSock2.h>

#define MAX_IP_LENGTH 16
#define MAX_URL_LENGTH 65
#define MAX_FILE_NAME_LENGTH 100
#define MAX_IP_URL_REFLECT_TABLE_LENGTH 1000
#define MAX_ID_TARNSFER_TABLE_LENGTH 100
#define MAX_CACHE_LENGTH 10
#define MAX_BUF_SIZE 513
using namespace std;

struct sockaddr_in localName, externName;//AF_INET��ַ
struct sockaddr_in client, out;

//�����
int Number=0;
bool IPV4 = true;

int lengthClient = sizeof(client);
SOCKET localSocket, outSocket; //�����׽��ֺ��ⲿ�׽���
WSADATA WsaData;  //�洢Windows�׽��ֳ�ʼ����Ϣ

//debug�ȼ�
int debugLevel = 0;

//dnsrelay�ļ�·��
char filePath[MAX_FILE_NAME_LENGTH] = "C:\\Users\\starry_sky\\Desktop\\���������γ����\\DNS\\Release\\dnsrelay.txt";

//�ⲿDNS������IP��ַ
char outDNSServerIP[MAX_IP_LENGTH] = "114.114.114.114";

//����IP��URL���ձ�
int TotalTableNumber = 0;
int CurrentTableNumber = 0;
char IPTable[MAX_IP_URL_REFLECT_TABLE_LENGTH][MAX_IP_LENGTH];
char URLTable[MAX_IP_URL_REFLECT_TABLE_LENGTH][MAX_URL_LENGTH];

//IDת����
int CurrentIDNumber = 0;
unsigned short oldIDtable[MAX_ID_TARNSFER_TABLE_LENGTH];
bool isDone[MAX_ID_TARNSFER_TABLE_LENGTH];
struct sockaddr_in IDClient[MAX_ID_TARNSFER_TABLE_LENGTH];

//cache�����洢�ⲿ��ѯ��IP��URL
int CacheCount = 0;
int TotalCacheNumber = 0;
int CurrentCacheNumber = 0;
char URLCache[MAX_CACHE_LENGTH][MAX_URL_LENGTH];
char IPCache[MAX_CACHE_LENGTH][MAX_IP_LENGTH];

void convertToURL(char* url, char* requestURL);
void outPutCurrentTime();
