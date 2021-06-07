#pragma once

#include "header.h"

extern const char* UPPER_DNS;
extern const char* HOST_FILE_LOC;
extern cmdLevel LEVEL;


typedef unsigned int UINT32;
enum ADDR_TYPE { BLOCKED = 100, CACHED, ADDR_NOT_FOUND };


/**
 * host表项
 * ip_addr :				ip地址
 * webaddr :				域名
 * type :
 */
typedef struct host_item
{
	UINT32 ip_addr;
	char* webaddr;
	ADDR_TYPE type;
}host_item;

//后来学习到的地址存入cache

/**
 * cache表项
 * ip_addr :				ip地址
 * webaddr :				域名
 * ttl :					该表项的生命周期（每查找一次，如果有用上，更新为50；如果没用上，ttl--）
 * occupied:				该表项是否被使用
 */
typedef struct cache_item
{
	UINT32 ip_addr;
	char* webaddr;
	int ttl;
	int occupied;
}cache_item;



//从dnsrelay.txt中读取ipaddr，domain，存入hosts_list中
//dnsrelay.txt中不能有多余的空行，部分域名返回的ip会出现错误
//每次读取一整行，再根据空格分开ip和域名
void readHost();

void writeCache();

//查找域名，并返回对应的ip地址（没找到为0.0.0.0），返回查找类型（blocked，cached，notfound）
ADDR_TYPE getAddrType(char*, UINT32*, int t_id, DNSRequest *req);

/**
 *		根据域名类型确定发送给客户端的字节流
 *		ori_packet	从客户端接收到的报文
 *		old_id		原来的id
 *		ip_addr		ip地址
 *		addr_type	域名类型
 *		sendbuflen	发送字长
 *		char *		发送给客户端的字节流
 */
char* getDNSResult(DNSPacket* ori_packet, int old_id, UINT32 ip_addr, ADDR_TYPE addr_type, int *sendbuflen);

