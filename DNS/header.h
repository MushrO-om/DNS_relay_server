#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <thread>
#include <mutex>
#include <time.h>
#pragma comment (lib, "Ws2_32.lib")

#define DNS_PORT 53				//DNS serves on port 53
#define DEFAULT_BUFLEN 1024
#define DNS_HEADER_LEN 12
#define MAX_HOST_ITEM 1200
#define MAX_CACHED_ITEM 200
#define MAX_REQ 1000

#define CACHE_FILE_LOC "dns_cache.txt"
#define MAX_THREAD 5
#define MAX_REQ_TTL 10
#define MAX_CACHE_TTL 50

extern const char* UPPER_DNS;
extern const char* HOST_FILE_LOC;


typedef unsigned short ushort;
enum Query_QR { Q_QUERY = 0, Q_RESPONSE = 1 };


/**
 * @brief : DNS����ͷ��
 * id : 2 Bytes:			����id��һ������ͻش�����ͬ
 * flags(2 Bytes):
 * QR : 1 bit               0��ѯ / 1��Ӧ
 * Opcode : 4 bit           0��׼��ѯ / 1�����ѯ / 2������״̬����
 * AA : 1 bit               ��ʾ��Ȩ�ش�
 * TC : 1 bit               ��ʾ���Խض�
 * RD : 1 bit               ��ʾ�����ݹ��ѯ
 * RA : 1 bit               ��ʾ���õݹ��ѯ
 * Z : 3 bits               ����
 * Rcode : 4 bit            �����룺0û�в�� / 2���������� / 3���ֲ��
 * QDCount : 2 Bytes		DNS ��ѯ�������Ŀ
 * ANCount : 2 Bytes		DNS ��Ӧ����Ŀ
 * NSCount : 2 Bytes		Ȩ�����Ʒ���������Ŀ
 * ARCount : 2 Bytes		����ļ�¼��Ŀ
 */
typedef struct DnsHeader
{
	ushort h_id;
	bool h_qr;
	ushort h_opcode;
	bool h_aa;
	bool h_tc;
	bool h_rd;
	bool h_ra;
	char h_rcode;
	ushort h_QDCount;
	ushort h_ANCount;
	ushort h_NSCount;
	ushort h_ARCount;
} DNSHeader;

/**
 * DNS����ѯ�ʲ���
 * Name(unknown Bytes):
 * Type : 2 Bytes			ͨ����ѯ����Ϊ A ���ͣ���ʾ��������ȡ��Ӧ�� IP ��ַ
 * Class : 2 Bytes          ��ַ���ͣ�ͨ��Ϊ��������ַ��ֵΪ 1
 */
typedef struct DnsQuery
{
	char* q_qname;
	ushort q_qtype;
	ushort q_qclass;
}DNSQuery;

/**
* DNS���Ĵ𸴲���
* Name(unknown Bytes):	��ѯ�ʵ�����һ��
* Type : 2 Bytes        ͨ����ѯ����Ϊ A ���ͣ���ѯ�ʲ���һ��
* Class : 2 Bytes       ��ַ���ͣ�ͨ��Ϊ��������ַ��ֵΪ 1
*TTL:4 Bytes            ��������
*RDLENGTH��2 Bytes      ��Դ���ݳ���
*RDATA��������           ��Դ���ݵ�����
*/

typedef struct DnsResponse
{
	char* r_name;
	ushort r_type;
	ushort r_class;
	int r_ttl;
	ushort r_rdlength;
	char* r_rdata;
}DNSResponse;

/**
 * DNS��������
 * p_qr:					��ע�ǲ�ѯ����(QUERY)������Ӧ����(RESPONSE)
 * p_header                                �����ײ�
 * p_qpointer[50] :                      DNSQuery����
 * p_rpointer[50] :			DNSResponse����
 */
typedef struct DnsPacket
{
	Query_QR p_qr;
	DNSHeader* p_header;
	DNSQuery* p_qpointer[50];
	DNSResponse* p_rpointer[50];
}DNSPacket;

/**
 * DNS����
 * processed:				��ע�������Ƿ����ڱ�����
 * old_id:					client���͵�id
 * new_id:					���б�Ҫ�����͸�DNS_SERVER��id�����ݴ����̺߳Ž��л���
 * packet :					DNS����
 * client_addr :			����DNS����Ŀͻ��˵�ַ
 * int client_addr_len :	����DNS����Ŀͻ��˵�ַ��С
 */
typedef struct DnsRequest
{
	bool processed;
	int old_id;
	int new_id;
	DNSPacket* packet;
	struct sockaddr_in client_addr;
	int client_addr_len;
}DNSRequest;

/**
 * DNS����ر���
 * available :				�ñ����Ƿ����δ���������
 * req :					DNS����
 * startTime��                               ����ʱ��
 */
typedef struct RequestPOOL
{
	bool available;
	DNSRequest* req;
	time_t startTime;
}ReqPool;

enum cmdLevel {
	ZEROTH,
	FIRST,
	SECOND
};//���еȼ� [��|-d|-dd]

extern cmdLevel LEVEL;


//�������壬�����ͻ��˷��������󲢼��������
int dnsRelay();

//��ʼ��sock���󶨶˿�53
//0����ɹ�����������ʧ��
int initDNSServer(SOCKET*);

void getParameter(int argc, char** argv);	//��ȡ���в���

/**
 *		ѯ���̴߳�����
 * 
 *		const char* upper_DNS_addr DNS��������ַ
 *		SOCKET Listen_Sokcet �����߳�
 *		int t_id �߳�id
 * 
 *		�̴߳��������ȡ�����󣬸�������������в�ͬ����Ĳ���
 *		�̴߳������Ĳ������������û���ָ�룬ָ��ֻ��ָ��������const char*
 *		�����߼�������BLOCKED����CACHED����ݵõ���ip�����µ�Ӧ���ķ��ظ�client
 *		�����߼�������NOT_FOUND�򽫱��ķ���DNS_SERVER��ע��Ҫ����id�����ٽ��õ��ı��ķ��ظ�client������һ�߳���ɣ�
 */
void CounsultThreadHandle(const char*, SOCKET, int);


/**
 *		����DNS�̴߳�����
 * 
 *		SOCKET upper_dns_socket DNS�����߳�
 *		SOCKET listen_sokcet �ͻ��˼����߳�
 *		int t_id �߳�id
 * 
 *		������DNS�������ģ����յ������޸�id��ͨ���ͻ��˼����̷߳����ͻ���
 */
void UpperThreadHandle(SOCKET, SOCKET, int);