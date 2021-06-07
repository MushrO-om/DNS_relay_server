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
 * @brief : DNS报文头部
 * id : 2 Bytes:			报文id，一对请求和回答报文相同
 * flags(2 Bytes):
 * QR : 1 bit               0查询 / 1响应
 * Opcode : 4 bit           0标准查询 / 1反向查询 / 2服务器状态请求
 * AA : 1 bit               表示授权回答
 * TC : 1 bit               表示可以截断
 * RD : 1 bit               表示期望递归查询
 * RA : 1 bit               表示可用递归查询
 * Z : 3 bits               保留
 * Rcode : 4 bit            返回码：0没有差错 / 2服务器错误 / 3名字差错
 * QDCount : 2 Bytes		DNS 查询请求的数目
 * ANCount : 2 Bytes		DNS 响应的数目
 * NSCount : 2 Bytes		权威名称服务器的数目
 * ARCount : 2 Bytes		额外的记录数目
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
 * DNS报文询问部分
 * Name(unknown Bytes):
 * Type : 2 Bytes			通常查询类型为 A 类型，表示由域名获取对应的 IP 地址
 * Class : 2 Bytes          地址类型，通常为互联网地址，值为 1
 */
typedef struct DnsQuery
{
	char* q_qname;
	ushort q_qtype;
	ushort q_qclass;
}DNSQuery;

/**
* DNS报文答复部分
* Name(unknown Bytes):	和询问的域名一致
* Type : 2 Bytes        通常查询类型为 A 类型，与询问部分一致
* Class : 2 Bytes       地址类型，通常为互联网地址，值为 1
*TTL:4 Bytes            生命周期
*RDLENGTH：2 Bytes      资源数据长度
*RDATA：不定长           资源数据的内容
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
 * DNS完整报文
 * p_qr:					标注是查询报文(QUERY)，还是应答报文(RESPONSE)
 * p_header                                报文首部
 * p_qpointer[50] :                      DNSQuery部分
 * p_rpointer[50] :			DNSResponse部分
 */
typedef struct DnsPacket
{
	Query_QR p_qr;
	DNSHeader* p_header;
	DNSQuery* p_qpointer[50];
	DNSResponse* p_rpointer[50];
}DNSPacket;

/**
 * DNS请求
 * processed:				标注该请求是否正在被处理
 * old_id:					client发送的id
 * new_id:					若有必要，发送给DNS_SERVER的id，根据处理线程号进行换算
 * packet :					DNS报文
 * client_addr :			发送DNS请求的客户端地址
 * int client_addr_len :	发送DNS请求的客户端地址大小
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
 * DNS请求池表项
 * available :				该表项是否存有未处理的请求
 * req :					DNS请求
 * startTime：                               发起时间
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
};//运行等级 [无|-d|-dd]

extern cmdLevel LEVEL;


//函数主体，监听客户端发来的请求并加入请求池
int dnsRelay();

//初始化sock，绑定端口53
//0代表成功，其它代表失败
int initDNSServer(SOCKET*);

void getParameter(int argc, char** argv);	//获取运行参数

/**
 *		询问线程处理函数
 * 
 *		const char* upper_DNS_addr DNS服务器地址
 *		SOCKET Listen_Sokcet 监听线程
 *		int t_id 线程id
 * 
 *		线程从请求池中取出请求，根据域名种类进行不同情况的操作
 *		线程处理函数的参数不能有引用或者指针，指针只能指向常量，如const char*
 *		处理逻辑：若是BLOCKED或者CACHED则根据得到的ip构造新的应答报文发回给client
 *		处理逻辑：若是NOT_FOUND则将报文发给DNS_SERVER（注意要更改id），再将得到的报文发回给client（由另一线程完成）
 */
void CounsultThreadHandle(const char*, SOCKET, int);


/**
 *		监听DNS线程处理函数
 * 
 *		SOCKET upper_dns_socket DNS监听线程
 *		SOCKET listen_sokcet 客户端监听线程
 *		int t_id 线程id
 * 
 *		持续从DNS监听报文，若收到，则修改id并通过客户端监听线程发给客户端
 */
void UpperThreadHandle(SOCKET, SOCKET, int);