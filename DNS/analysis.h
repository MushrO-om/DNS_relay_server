#pragma once

#include "header.h"

extern const char* UPPER_DNS;
extern const char* HOST_FILE_LOC;
extern cmdLevel LEVEL;


typedef unsigned int UINT32;
enum ADDR_TYPE { BLOCKED = 100, CACHED, ADDR_NOT_FOUND };


/**
 * host����
 * ip_addr :				ip��ַ
 * webaddr :				����
 * type :
 */
typedef struct host_item
{
	UINT32 ip_addr;
	char* webaddr;
	ADDR_TYPE type;
}host_item;

//����ѧϰ���ĵ�ַ����cache

/**
 * cache����
 * ip_addr :				ip��ַ
 * webaddr :				����
 * ttl :					�ñ�����������ڣ�ÿ����һ�Σ���������ϣ�����Ϊ50�����û���ϣ�ttl--��
 * occupied:				�ñ����Ƿ�ʹ��
 */
typedef struct cache_item
{
	UINT32 ip_addr;
	char* webaddr;
	int ttl;
	int occupied;
}cache_item;



//��dnsrelay.txt�ж�ȡipaddr��domain������hosts_list��
//dnsrelay.txt�в����ж���Ŀ��У������������ص�ip����ִ���
//ÿ�ζ�ȡһ���У��ٸ��ݿո�ֿ�ip������
void readHost();

void writeCache();

//���������������ض�Ӧ��ip��ַ��û�ҵ�Ϊ0.0.0.0�������ز������ͣ�blocked��cached��notfound��
ADDR_TYPE getAddrType(char*, UINT32*, int t_id, DNSRequest *req);

/**
 *		������������ȷ�����͸��ͻ��˵��ֽ���
 *		ori_packet	�ӿͻ��˽��յ��ı���
 *		old_id		ԭ����id
 *		ip_addr		ip��ַ
 *		addr_type	��������
 *		sendbuflen	�����ֳ�
 *		char *		���͸��ͻ��˵��ֽ���
 */
char* getDNSResult(DNSPacket* ori_packet, int old_id, UINT32 ip_addr, ADDR_TYPE addr_type, int *sendbuflen);

