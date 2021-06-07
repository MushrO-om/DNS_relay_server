#pragma once
#include "header.h"

extern const char* UPPER_DNS;
extern const char* HOST_FILE_LOC;
extern cmdLevel LEVEL;


//从请求池中获取一个请求
DNSRequest* getDNSRequest();

/**
 *		向请求池里添加一个请求
 *		int 返回在请求池中的位置
 */
int addDNSRequestPool(DNSRequest*);

/**
 *		从请求池里删除一个请求
 *		int 在请求池中的位置
 *		DNSRequest* 该请求的指针
 */
DNSRequest * finishDNSRequest(int); 

void free_req(DNSRequest*);