#pragma once
#include "analysis.h"
#include "translate.h"

extern host_item* hosts_list[];
extern cache_item* cached_list[];
extern int host_counter;
extern const char* UPPER_DNS;
extern const char* HOST_FILE_LOC;
extern cmdLevel LEVEL;

void readHost()
{
	// Prepare reading
	FILE* fp = fopen(HOST_FILE_LOC, "r");
	if (fp == NULL)
	{
		printf("\n[error] [load host]: dnsrelay.txt open error...\n");
		exit(1);
	}

	// Start reading 
	char ipaddr[DEFAULT_BUFLEN];
	char domain[DEFAULT_BUFLEN];
	int cnt = 0;
	while (!feof(fp))
	{
		//读取字符串，每次读取一行，包括换行符
		fgets(ipaddr, DEFAULT_BUFLEN, fp);
		for (int i = 0; i < DEFAULT_BUFLEN; i++)
		{
			//遍历读取到的字符串，遇到空格，空格前的部分是ip地址
			if (ipaddr[i] == ' ')
			{
				//空格改为字符串结束符，ip单独成串
				ipaddr[i] = '\0';
				//把这之后的串存入domain
				strcpy(domain, ipaddr + i + 1);
				//遇到换行，说明前面部分为域名，把换行符改成结束符，域名单独成串
				if (domain[strlen(domain) - 1] == '\n')
					domain[strlen(domain) - 1] = '\0';
				//文件结束（最后一行）
				else
					domain[strlen(domain)] = '\0';
				break;
			}
		}
		hosts_list[cnt] = (host_item*)malloc(sizeof(host_item));
		hosts_list[cnt]->webaddr = (char*)malloc(DEFAULT_BUFLEN);
		inet_pton(AF_INET, ipaddr, &hosts_list[cnt]->ip_addr);
		strcpy(hosts_list[cnt]->webaddr, domain);

		//如果表项的ip为0，则该域名blocked，即0.0.0.0，错误，返回“域名不存在”的报错信息，故类型为blocked
		if (hosts_list[cnt]->ip_addr == 0)
			hosts_list[cnt]->type = BLOCKED;
		else
			hosts_list[cnt]->type = CACHED;
		cnt++;

	}
	host_counter = cnt - 1;
	if(LEVEL==FIRST) printf("\nload %d host from %s successfully\n", cnt, HOST_FILE_LOC);
	if(LEVEL==SECOND) printf("\n[load host]: load %d host from %s successfully\n", cnt, HOST_FILE_LOC);
	fclose(fp);
}

//定期更新cache文件
void writeCache() {
	FILE* fp = fopen(CACHE_FILE_LOC, "w");
	if (fp == NULL)
	{
		printf("\n[error] [cache update]: dns_cache.txt open error...\n");
		exit(1);
	}

	for (int cache_i = 0; cache_i < MAX_CACHED_ITEM; cache_i++) {
		//跳过空表项
		if (cached_list[cache_i]->occupied == 0) continue;
		char tmp[DEFAULT_BUFLEN];
		inet_ntop(AF_INET,&cached_list[cache_i]->ip_addr,tmp,DEFAULT_BUFLEN);
		fputs(tmp,fp);
		fputc(' ',fp);
		fputs(cached_list[cache_i]->webaddr, fp);
		fputc('\n', fp);
	}
	if (LEVEL == SECOND) printf("\n\n[cache update]: write %s successfully\n\n", CACHE_FILE_LOC);
	fclose(fp);
}

/*
 * getAddrType tells if the searched address is in host list
 * returns ADDR_TYPE (ADDR_CACHED, ADDR_BLOCKED, ADDR_NOT_FOUND)
 * returns real ip if found, 0.0.0.0 if not found.
 */

 //获取地址类型（blocked，cached，addr_not_found）
 //addr为域名，ip为ip地址（即搜索结果）
ADDR_TYPE getAddrType(char* addr, UINT32* ip, int t_id, DNSRequest *req)
{
	int i;
	*ip = 0x0;
	//tmp_addr ---- domain name
	char* tmp_addr = (char*)malloc(DEFAULT_BUFLEN);

	strcpy(tmp_addr, addr);

	for (i = 0; i < strlen(addr); i++)
	{
		// 将不可见的字符转化为.方便对比
		if (tmp_addr[i] < 0x20)
			tmp_addr[i] = '.';
		//大小写统一为小写
		else if (tmp_addr[i] >= 'A' && tmp_addr[i] <= 'Z')
		{
			tmp_addr[i] -= 'A' - 'a';
		}
	}
	time_t timep;
	time(&timep);
	char tmp[64];
	strftime(tmp, sizeof(tmp), "%Y-%m-%d %H-%M-%S", localtime(&timep));
	if (LEVEL == FIRST) printf("%s\tClient(%s)\t%s\n", tmp, inet_ntoa(req->client_addr.sin_addr), tmp_addr + 1);

	if(LEVEL==SECOND) printf("\n[Consulting Thread %d] [Analyse]: Domain name: %s\n", t_id, tmp_addr+1);

	 // 从host列表中找到ip
	for (i = 0; i <= host_counter; i++)
	{
		//如果host表中域名是待查找域名的子串（在host表中找到了）
		//问题：为什么不直接strcmp？
		if (strstr(tmp_addr, hosts_list[i]->webaddr))
		{
			//找到了域名对应的ip
			*ip = htonl(hosts_list[i]->ip_addr);
			char tmp[DEFAULT_BUFLEN];
			inet_ntop(AF_INET, &hosts_list[i]->ip_addr, tmp, DEFAULT_BUFLEN);
			if (LEVEL == SECOND) printf("\n[Consulting Thread %d] [HOST HIT]: IP: %s\tHost ID: %d\n", t_id, tmp, i);
			if (*ip != 0)
				return CACHED;
			else
				//如果ip是0.0.0.0，返回blocked
				return BLOCKED;
		}
	}

	//在cached表中查找
	for (i = 0; i < MAX_CACHED_ITEM; i++)
	{
		if (!cached_list[i]->occupied) continue;
		if (strstr(tmp_addr, cached_list[i]->webaddr))
		{
			*ip = htonl(cached_list[i]->ip_addr);
			char tmp[DEFAULT_BUFLEN];
			inet_ntop(AF_INET, &cached_list[i]->ip_addr, tmp, DEFAULT_BUFLEN);
			if (LEVEL == SECOND) printf("\n[Consulting Thread %d] [CACHE HIT]: IP: %s\tCache ID: %d\n", t_id, tmp, i);
			//如果此表项用上了，更新生命周期
			cached_list[i]->ttl = MAX_CACHE_TTL;
			if (*ip != 0)
				return CACHED;
			else
				//如果ip是0.0.0.0，返回blocked
				return BLOCKED;

		}
		//如果此表项内容没用上，生命周期--直到0时丢弃
		else
		{
			(cached_list[i]->ttl)--;
			if (cached_list[i]->ttl == 0)
				cached_list[i]->occupied = false;
		}
	}
	return ADDR_NOT_FOUND;
}

//获取给客户端发回的应答报文（报文流）
//执行该函数的包的类型只可能是2种,BLOCKED或CACHED
char* getDNSResult(DNSPacket* ori_packet, int old_id, UINT32 ip_addr, ADDR_TYPE addr_type, int *sendbuflen)
{
	DNSPacket* ret_packet = (DNSPacket*)malloc(sizeof(DNSPacket));
	DNSHeader* ret_header = (DNSHeader*)malloc(sizeof(DNSHeader));
	DNSQuery* ret_query = ori_packet->p_qpointer[0];
	DNSResponse* ret_response = (DNSResponse*)malloc(sizeof(DNSResponse));
	ushort ret_id;

	//如果查到的ip是0.0.0.0，创建一个新的答复报文
	if (addr_type == BLOCKED)
	{
		//Construct new DNSHeader
		ret_header->h_id = ori_packet->p_header->h_id;
		ret_header->h_qr = 1;//类型为答复报文
		//ret_header->h_opcode = ori_packet->p_header->h_opcode;
		ret_header->h_opcode = 0;
		ret_header->h_aa = 0;
		ret_header->h_tc = 0;
		ret_header->h_rd = 1;
		ret_header->h_ra = 1;
		ret_header->h_rcode = 3;
		ret_header->h_QDCount = 0;//答复报文没有问题和答案字段，说明产生了错误
		ret_header->h_ANCount = 0;
		ret_header->h_NSCount = 0;
		ret_header->h_ARCount = 0;

		//没有问题和回答字段
		ret_packet->p_header = ret_header;
		ret_packet->p_qpointer[0] = NULL;
		ret_packet->p_rpointer[0] = NULL;
		ret_packet->p_qr = Q_RESPONSE;
	}
	//如果类型是cached，即在表中查到了
	else
	{
		//Construct new DNSResponse
		ret_response->r_name = ori_packet->p_qpointer[0]->q_qname;
		ret_response->r_type = 1;
		ret_response->r_class = ori_packet->p_qpointer[0]->q_qclass;
		ret_response->r_ttl = 0x100;
		ret_response->r_rdlength = 4;
		ret_response->r_rdata = (char*)malloc(sizeof(UINT32) + 1);
		*(UINT32*)(ret_response->r_rdata) = ip_addr;

		//Construct new DNSHeader
		ret_header->h_id = ori_packet->p_header->h_id;
		ret_header->h_qr = 1;
		//ret_header->h_opcode = ori_packet->p_header->h_opcode;
		ret_header->h_opcode = 0;
		ret_header->h_aa = 0;
		ret_header->h_tc = 0;
		ret_header->h_rd = 1;
		ret_header->h_ra = 1;
		ret_header->h_rcode = 0;
		ret_header->h_QDCount = 1;
		ret_header->h_ANCount = 1;
		ret_header->h_NSCount = 0;
		ret_header->h_ARCount = 0;

		ret_packet->p_header = ret_header;
		ret_packet->p_qpointer[0] = ret_query;
		ret_packet->p_rpointer[0] = ret_response;
		ret_packet->p_qr = Q_RESPONSE;
	}
	//发回的答复报文的id是发来的id，而不是重新分配后的id
	//报文的id都是旧的，新分配的是请求中的id
	ret_packet->p_header->h_id = old_id;

	char* sendbuf = (char*)malloc(DEFAULT_BUFLEN);
	//结构体转为报文流
	sendbuf = packDNSPacket(ret_packet, sendbuflen);

	return sendbuf;
}

