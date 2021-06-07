#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include "header.h"

extern const char* UPPER_DNS;
extern const char* HOST_FILE_LOC;
extern cmdLevel LEVEL;

/**
 *		将src指向的char*转化为DNSHeader
 * 
 *		src 源指针
 *		ret_prt 返回指针
 * 
 *		Header长度固定为12 Bytes
 *		函数结束时ret_ptr被修改为DNSHeader的下一个地址
 *		src不会被修改
 */
DNSHeader* fromDNSHeader(char* src, char** ret_ptr);

/**
 *		将src指向的char*转化为DNSQuery

 *		src 源指针
 *		ret_prt 返回指针
 * 
 *		函数结束时ret_ptr被修改为DNSQuery的下一个地址
 *		src不会被修改
 */
DNSQuery* fromDNSQuery(char* src, char** ret_ptr);

/**
 *		将src指向的char*转化为DNSResponse
 * 
 *		src 源指针
 *		head DNS报文的头指针
 *		ret_prt 返回指针
 * 
 *		函数结束时ret_ptr被修改为DNSReponse的下一个地址
 *		src不会被修改
 */
DNSResponse* fromDNSResponse(char* src, char* head, char** ret_ptr);

/**
 *		将DNSHeader*指向的内容转化为网络二进制字节流
 * 
 *		DNSHeader* 源指针
 * 
 *		flags部分的大小为2 Bytes，采用了按位与(&)和左移位(<<)的方法构造
 *		ret_s是最终返回的指针
 *		tmp_s是实际进行字段操作的指针
 */
char* toDNSHeader(DNSHeader*);

/**
 *		将DNSQueryr*指向的内容转化为网络二进制字节流
 * 
 *		DNSQueryr* 源指针
 *		char *
 * 
 *		tmp_u_short_pointer和tmp_char_pointer指向的内容相同，只不过指向的范围不同(2bytes 和 1bytes)
 *		qname的长度不能确定，但是以'\0'结尾，需要使用strlen获取
 */
char* toDNSQuery(DNSQuery*);

/**
 *		将DNSResponse*指向的内容转化为网络二进制字节流
 * 
 *		DNSResponse* 源指针
 *		char *
 * 
 *		使用方法与toDNSQuery()相同
 */
char* toDNSResponse(DNSResponse*);

/**
 *		将网络二进制字节流指向的内容转化为DNSPacket
 * 
 *		char* 源指针
 * 
 *		函数调用了fromDNSHeader()、fromDNSQuery()和fromDNSResponse()
 *		根据DNS报文格式进行转换
 *		根据实际需要，不对所有Query和Response进行转换，只分别对第一个进行转换
 */
DNSPacket* unpackDNSPacket(char*);

/**
 *		将DNSPacket*指向的内容转化为网络二进制字节流
 * 
 *		DNSPacket* 源指针
 *		int& 字节流长度

 *		unpackDNSPacket的逆过程
 */
char* packDNSPacket(DNSPacket*, int*);