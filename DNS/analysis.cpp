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
		//��ȡ�ַ�����ÿ�ζ�ȡһ�У��������з�
		fgets(ipaddr, DEFAULT_BUFLEN, fp);
		for (int i = 0; i < DEFAULT_BUFLEN; i++)
		{
			//������ȡ�����ַ����������ո񣬿ո�ǰ�Ĳ�����ip��ַ
			if (ipaddr[i] == ' ')
			{
				//�ո��Ϊ�ַ�����������ip�����ɴ�
				ipaddr[i] = '\0';
				//����֮��Ĵ�����domain
				strcpy(domain, ipaddr + i + 1);
				//�������У�˵��ǰ�沿��Ϊ�������ѻ��з��ĳɽ����������������ɴ�
				if (domain[strlen(domain) - 1] == '\n')
					domain[strlen(domain) - 1] = '\0';
				//�ļ����������һ�У�
				else
					domain[strlen(domain)] = '\0';
				break;
			}
		}
		hosts_list[cnt] = (host_item*)malloc(sizeof(host_item));
		hosts_list[cnt]->webaddr = (char*)malloc(DEFAULT_BUFLEN);
		inet_pton(AF_INET, ipaddr, &hosts_list[cnt]->ip_addr);
		strcpy(hosts_list[cnt]->webaddr, domain);

		//��������ipΪ0���������blocked����0.0.0.0�����󣬷��ء����������ڡ��ı�����Ϣ��������Ϊblocked
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

//���ڸ���cache�ļ�
void writeCache() {
	FILE* fp = fopen(CACHE_FILE_LOC, "w");
	if (fp == NULL)
	{
		printf("\n[error] [cache update]: dns_cache.txt open error...\n");
		exit(1);
	}

	for (int cache_i = 0; cache_i < MAX_CACHED_ITEM; cache_i++) {
		//�����ձ���
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

 //��ȡ��ַ���ͣ�blocked��cached��addr_not_found��
 //addrΪ������ipΪip��ַ�������������
ADDR_TYPE getAddrType(char* addr, UINT32* ip, int t_id, DNSRequest *req)
{
	int i;
	*ip = 0x0;
	//tmp_addr ---- domain name
	char* tmp_addr = (char*)malloc(DEFAULT_BUFLEN);

	strcpy(tmp_addr, addr);

	for (i = 0; i < strlen(addr); i++)
	{
		// �����ɼ����ַ�ת��Ϊ.����Ա�
		if (tmp_addr[i] < 0x20)
			tmp_addr[i] = '.';
		//��СдͳһΪСд
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

	 // ��host�б����ҵ�ip
	for (i = 0; i <= host_counter; i++)
	{
		//���host���������Ǵ������������Ӵ�����host�����ҵ��ˣ�
		//���⣺Ϊʲô��ֱ��strcmp��
		if (strstr(tmp_addr, hosts_list[i]->webaddr))
		{
			//�ҵ���������Ӧ��ip
			*ip = htonl(hosts_list[i]->ip_addr);
			char tmp[DEFAULT_BUFLEN];
			inet_ntop(AF_INET, &hosts_list[i]->ip_addr, tmp, DEFAULT_BUFLEN);
			if (LEVEL == SECOND) printf("\n[Consulting Thread %d] [HOST HIT]: IP: %s\tHost ID: %d\n", t_id, tmp, i);
			if (*ip != 0)
				return CACHED;
			else
				//���ip��0.0.0.0������blocked
				return BLOCKED;
		}
	}

	//��cached���в���
	for (i = 0; i < MAX_CACHED_ITEM; i++)
	{
		if (!cached_list[i]->occupied) continue;
		if (strstr(tmp_addr, cached_list[i]->webaddr))
		{
			*ip = htonl(cached_list[i]->ip_addr);
			char tmp[DEFAULT_BUFLEN];
			inet_ntop(AF_INET, &cached_list[i]->ip_addr, tmp, DEFAULT_BUFLEN);
			if (LEVEL == SECOND) printf("\n[Consulting Thread %d] [CACHE HIT]: IP: %s\tCache ID: %d\n", t_id, tmp, i);
			//����˱��������ˣ�������������
			cached_list[i]->ttl = MAX_CACHE_TTL;
			if (*ip != 0)
				return CACHED;
			else
				//���ip��0.0.0.0������blocked
				return BLOCKED;

		}
		//����˱�������û���ϣ���������--ֱ��0ʱ����
		else
		{
			(cached_list[i]->ttl)--;
			if (cached_list[i]->ttl == 0)
				cached_list[i]->occupied = false;
		}
	}
	return ADDR_NOT_FOUND;
}

//��ȡ���ͻ��˷��ص�Ӧ���ģ���������
//ִ�иú����İ�������ֻ������2��,BLOCKED��CACHED
char* getDNSResult(DNSPacket* ori_packet, int old_id, UINT32 ip_addr, ADDR_TYPE addr_type, int *sendbuflen)
{
	DNSPacket* ret_packet = (DNSPacket*)malloc(sizeof(DNSPacket));
	DNSHeader* ret_header = (DNSHeader*)malloc(sizeof(DNSHeader));
	DNSQuery* ret_query = ori_packet->p_qpointer[0];
	DNSResponse* ret_response = (DNSResponse*)malloc(sizeof(DNSResponse));
	ushort ret_id;

	//����鵽��ip��0.0.0.0������һ���µĴ𸴱���
	if (addr_type == BLOCKED)
	{
		//Construct new DNSHeader
		ret_header->h_id = ori_packet->p_header->h_id;
		ret_header->h_qr = 1;//����Ϊ�𸴱���
		//ret_header->h_opcode = ori_packet->p_header->h_opcode;
		ret_header->h_opcode = 0;
		ret_header->h_aa = 0;
		ret_header->h_tc = 0;
		ret_header->h_rd = 1;
		ret_header->h_ra = 1;
		ret_header->h_rcode = 3;
		ret_header->h_QDCount = 0;//�𸴱���û������ʹ��ֶΣ�˵�������˴���
		ret_header->h_ANCount = 0;
		ret_header->h_NSCount = 0;
		ret_header->h_ARCount = 0;

		//û������ͻش��ֶ�
		ret_packet->p_header = ret_header;
		ret_packet->p_qpointer[0] = NULL;
		ret_packet->p_rpointer[0] = NULL;
		ret_packet->p_qr = Q_RESPONSE;
	}
	//���������cached�����ڱ��в鵽��
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
	//���صĴ𸴱��ĵ�id�Ƿ�����id�����������·�����id
	//���ĵ�id���Ǿɵģ��·�����������е�id
	ret_packet->p_header->h_id = old_id;

	char* sendbuf = (char*)malloc(DEFAULT_BUFLEN);
	//�ṹ��תΪ������
	sendbuf = packDNSPacket(ret_packet, sendbuflen);

	return sendbuf;
}

