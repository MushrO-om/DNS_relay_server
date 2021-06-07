#pragma once

#include "translate.h"

extern const char* UPPER_DNS;
extern const char* HOST_FILE_LOC;
extern cmdLevel LEVEL;

//src传递报文开始地址
DNSHeader* fromDNSHeader(char* src, char** ret_ptr)
{
	DNSHeader* new_q = (DNSHeader*)malloc(sizeof(DNSHeader));
	memset(new_q, 0, sizeof(DNSHeader));

	ushort* pointer = (ushort*)src;//pointer指向报文的头两个字节
	ushort cur_word = ntohs(*pointer);//大小端的转化，cur_word存储报文的头两个字节（id)

	//Get transaction ID
	new_q->h_id = cur_word;

	//Get flags
	cur_word = ntohs(*(++pointer));//pointer指向报文的第2、3字节
	new_q->h_qr = (bool)((cur_word & 0x8000) >> 15);//取首位（0表示request，1表示response）
	new_q->h_opcode = (ushort)((cur_word & 0x7800) >> 11);//取接下来的4位
	new_q->h_aa = (bool)((cur_word & 0x0400) >> 10);//各取1位
	new_q->h_tc = (bool)((cur_word & 0x0200) >> 9);
	new_q->h_rd = (bool)((cur_word & 0x0100) >> 8);
	new_q->h_ra = (bool)((cur_word & 0x0080) >> 7);
	//有3位z字段，保留
	new_q->h_rcode = (ushort)((cur_word & 0x000F));//最后4位

	//Get Counts（每个两字节）
	cur_word = ntohs(*(++pointer));//第4、5字节给QDCOUNT
	new_q->h_QDCount = cur_word;
	cur_word = ntohs(*(++pointer));
	new_q->h_ANCount = cur_word;
	cur_word = ntohs(*(++pointer));
	new_q->h_NSCount = cur_word;
	cur_word = ntohs(*(++pointer));
	new_q->h_ARCount = cur_word;

	//至此报头部分读取完毕，ret_ptr返回问题字段开始的地址
	*ret_ptr = (char*)(++pointer);
	return new_q;//返回根据报文格式化后的报头结构
}

DNSQuery* fromDNSQuery(char* src, char** ret_ptr)
{
	DNSQuery* new_q = (DNSQuery*)malloc(sizeof(DNSQuery));
	memset(new_q,0,sizeof(DNSQuery));

	int qname_len = 0;
	while (*(src + qname_len) != '\0') qname_len++;

	char* tmp_str = (char*)malloc(qname_len+1);
	strcpy(tmp_str, src);
	new_q->q_qname = tmp_str;

	src += (++qname_len);
	ushort* tmp = (ushort*)src;
	new_q->q_qtype = ntohs(*(tmp++));
	new_q->q_qclass = ntohs(*tmp);

	*ret_ptr = (char*)(++tmp);
	return new_q;
}

DNSResponse* fromDNSResponse(char* src, char* head, char** ret_ptr)
{
	DNSResponse* new_r = (DNSResponse*)malloc(sizeof(DNSResponse));
	memset(new_r, 0, sizeof(DNSResponse));

	char* s = (char*)malloc(256 * sizeof(char));
	memset(s,0, 256 * sizeof(char));
	int qname_length = 0;
	char* final_name_dst = src;
	bool name_jumped = false;

	char* name_pointer = src;
	//获取域名
	while (1)
	{
		if (*name_pointer == '\0')
		{
			s[qname_length] = '\0';
			if (name_jumped == false)
				final_name_dst = src + qname_length;
			break;
		}
		if (((*name_pointer) & 0xc0) == 0xc0)
		{
			int new_dst = ntohs(*((ushort*)name_pointer)) & 0x3f;
			new_dst += (int)head;
			name_jumped = true;
			final_name_dst = name_pointer + 2;
			name_pointer = (char*)new_dst;
			continue;
		}
		if (*name_pointer < 20)
		{
			int tmp_len = *name_pointer++;
			s[qname_length++] = tmp_len;
			for (int i = 0; i < tmp_len; i++)
				s[qname_length++] = *(name_pointer++);
		}
	}

	new_r->r_name = s;

	src = final_name_dst;
	ushort* tmp = (ushort*)src;
	new_r->r_type = ntohs(*(tmp++));
	new_r->r_class = ntohs(*(tmp++));
	new_r->r_ttl = ntohl(*((int*)tmp));
	tmp += 2;
	new_r->r_rdlength = ntohs(*(tmp++));

	src = (char*)tmp;
	s = (char*)malloc((new_r->r_rdlength + 1) * sizeof(char));
	memcpy(s, src, new_r->r_rdlength);
	s[new_r->r_rdlength] = '\0';
	new_r->r_rdata = s;

	*ret_ptr = src + new_r->r_rdlength;
	return new_r;
}

//把结构体的头部转换成字符串
char* toDNSHeader(DNSHeader* ret_h)
{
	ushort* tmp_s;
	char* ret_s;
	tmp_s = (ushort*)malloc(13 * sizeof(char));
	memset(tmp_s, 0, 13 * sizeof(char));
	ret_s = (char*)tmp_s;
	//tmp_s先用后++，前两字节为id
	*(tmp_s++) = htons((ushort)ret_h->h_id);

	*tmp_s = 0;
	ushort tags = 0;
	tags |= (ret_h->h_qr << 15);
	tags |= (ret_h->h_opcode << 11);
	tags |= (ret_h->h_aa << 10);
	tags |= (ret_h->h_tc << 9);
	tags |= (ret_h->h_rd << 8);
	tags |= (ret_h->h_ra << 7);
	tags |= (ret_h->h_rcode);
	*(tmp_s++) = htons(tags);
	*(tmp_s++) = htons(ret_h->h_QDCount);
	*(tmp_s++) = htons(ret_h->h_ANCount);
	*(tmp_s++) = htons(ret_h->h_NSCount);
	*(tmp_s++) = htons(ret_h->h_ARCount);

	//填上字符串结束符
	*(char*)tmp_s = '\0';
	return ret_s;
}

char* toDNSQuery(DNSQuery* ret_q)
{
	char* ret_s, * tmp_c;
	ushort* tmp_u;
	int tot_length;

	tot_length = strlen(ret_q->q_qname) + 6;
	ret_s = (char*)malloc(tot_length * sizeof(char));
	memset(ret_s, 0, tot_length * sizeof(char));
	tmp_c = ret_s;

	//Copy qname to reply message
	//temp_c用于填入域名（char字符串）
	//每一段的最后都要以\0结尾
	strcpy(tmp_c, ret_q->q_qname);
	tmp_c += strlen(ret_q->q_qname);
	*tmp_c = '\0';
	tmp_c++;
	tmp_u = (ushort*)tmp_c;

	//temp_u用于填入类型（unsighed short）
	*(tmp_u++) = htons(ret_q->q_qtype);
	*(tmp_u++) = htons(ret_q->q_qclass);

	//每一段的最后都要以\0结尾
	tmp_c = (char*)tmp_u;
	tmp_c = (char*)'\0';

	//最后返回全部询问字段
	return ret_s;
}

char* toDNSResponse(DNSResponse* ret_r)
{
	char* ret_s, * tmp_c;
	ushort* tmp_u;
	int tot_length;

	tot_length = strlen(ret_r->r_name) + 11 + ret_r->r_rdlength + 1;

	//rname
	ret_s = (char*)malloc(tot_length * sizeof(char));
	memset(ret_s, 0, tot_length * sizeof(char));

	tmp_c = ret_s;
	strcpy(tmp_c, ret_r->r_name);
	tmp_c += strlen(ret_r->r_name);
	*tmp_c = '\0';
	tmp_c++;
	tmp_u = (ushort*)tmp_c;

	//其它ushort和int
	*tmp_u++ = htons(ret_r->r_type);
	*tmp_u++ = htons(ret_r->r_class);
	*(int*)tmp_u = htonl(ret_r->r_ttl);
	tmp_u += 2;
	*tmp_u++ = htons(ret_r->r_rdlength);

	tmp_c = (char*)tmp_u;
	memcpy(tmp_c, ret_r->r_rdata, ret_r->r_rdlength);

	return ret_s;
}

//只转换第一个询问
//把报文（字节流）格式化存入结构体（输入存储进程序）
DNSPacket* unpackDNSPacket(char* buf)
{
	//cur_ptr指向报文开头地址，即报头的开头
	char* cur_ptr = buf, * ret_ptr;

	DNSPacket* dns_packet = (DNSPacket*)malloc(sizeof(DNSPacket));
	memset(dns_packet,0,sizeof(DNSPacket));

	// Read DNS Header
	//报头格式化
	dns_packet->p_header = fromDNSHeader(cur_ptr, &ret_ptr);
	//指针后移，移到问题字段的开头
	cur_ptr = ret_ptr;

	//读取QDCOUNT个问题字段
	for (int i = 0; i < dns_packet->p_header->h_QDCount; i++)
	{
		//问题字段格式化
		dns_packet->p_qpointer[i] = fromDNSQuery(cur_ptr, &ret_ptr);
		//指针后移
		cur_ptr = ret_ptr;
	}

	// Read DNS Response
	//如果有回答字段（如果是应答报文）
	if (dns_packet->p_header->h_ANCount > 0)
	{
		dns_packet->p_rpointer[0] = fromDNSResponse(cur_ptr, buf, &ret_ptr);
		cur_ptr = ret_ptr;
		dns_packet->p_header->h_ANCount = 1;
	}
	else
	{
		dns_packet->p_rpointer[0] = (DNSResponse*)malloc(sizeof(DNSResponse));
		memset(dns_packet->p_rpointer[0], 0, sizeof(DNSResponse));
		dns_packet->p_rpointer[0]->r_rdata = NULL;//没有回答字段就把rdata置null
	}
	//设置qr标志（用于判断该报文属于询问还是应答）
	dns_packet->p_qr = dns_packet->p_header->h_qr ? Q_RESPONSE : Q_QUERY;

	//返回格式化的报文结构体
	return dns_packet;
}

//把结构体存入报文流（从程序输出）
//len为返回的报文流的长度
char* packDNSPacket(DNSPacket* packet, int *len)
{
	char* new_header = toDNSHeader(packet->p_header);

	//Convert Query part and Header part
	//ret_string为返回的报文流字符串
	char* ret_string = (char*)malloc(DEFAULT_BUFLEN);
	memcpy(ret_string, new_header, DNS_HEADER_LEN);
	*len = DNS_HEADER_LEN;
	//如果问题只有一个
	if (packet->p_header->h_QDCount == 1)
	{
		char* new_query = toDNSQuery(packet->p_qpointer[0]);
		memcpy(ret_string + *len, new_query, strlen(packet->p_qpointer[0]->q_qname) + 5);
		*len += strlen(packet->p_qpointer[0]->q_qname) + 5;
		if (new_query) free(new_query);
	}

	// Convert DNSResponse if needed (packet is a response)
	//如果类型是答复报文，并且有回答字段
	if (packet->p_qr == Q_RESPONSE && packet->p_header->h_ANCount > 0)
	{
		char* new_response = toDNSResponse(packet->p_rpointer[0]);
		memcpy(ret_string + *len, new_response, strlen(packet->p_rpointer[0]->r_name) + 11 + packet->p_rpointer[0]->r_rdlength);
		*len += strlen(packet->p_rpointer[0]->r_name) + 11 + packet->p_rpointer[0]->r_rdlength;
		if (new_response) free(new_response);
	}

	return ret_string;
}