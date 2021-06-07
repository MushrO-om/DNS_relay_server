#pragma once
#include "header.h"

extern const char* UPPER_DNS;
extern const char* HOST_FILE_LOC;
extern cmdLevel LEVEL;


//��������л�ȡһ������
DNSRequest* getDNSRequest();

/**
 *		������������һ������
 *		int ������������е�λ��
 */
int addDNSRequestPool(DNSRequest*);

/**
 *		���������ɾ��һ������
 *		int ��������е�λ��
 *		DNSRequest* �������ָ��
 */
DNSRequest * finishDNSRequest(int); 

void free_req(DNSRequest*);