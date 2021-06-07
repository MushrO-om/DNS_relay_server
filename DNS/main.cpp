#pragma once
#include "header.h"
#include "translate.h"
#include "analysis.h"
#include "request_pool.h"

host_item* hosts_list[MAX_HOST_ITEM];
cache_item* cached_list[MAX_CACHED_ITEM];

ReqPool* request_pool;
std::mutex id_mutex, pool_mutex, req_counter_mutex, time_mutex, cache_mutex;
int req_counter = 0, host_counter = 0;
std::thread* dns_consulting_threads[MAX_THREAD];

const char* UPPER_DNS = "192.168.43.1";
const char* HOST_FILE_LOC = "dnsrelay.txt";
cmdLevel LEVEL = ZEROTH;

int main(int argc, char** argv)
{
	getParameter(argc, argv);//��ȡ���в���
	if (LEVEL != ZEROTH) {
		printf("Designed by Lan Xuechao & Chen Lianjie\n");
		printf("The IP of uppperDNS is [%s]\n", UPPER_DNS);
		printf("The path of local host file is [%s]\n", HOST_FILE_LOC);
	}
	dnsRelay();
	return 0;
}

void getParameter(int argc, char** argv)//��ȡ���в���
{
	for (int i = 1; i < argc; i++) {
		std::string s = argv[i];
		if (s == "-d")
			LEVEL = FIRST;
		else if (s == "-dd")
			LEVEL = SECOND;
		else if (s.find(".txt") != s.npos)
			HOST_FILE_LOC = argv[i];
		else
			UPPER_DNS = argv[i];
	}
}

int dnsRelay()
{
	// Initialize, load history data
	int res = 0;

	readHost();

	// Initialize Cached_list
	for (int i = 0; i < MAX_CACHED_ITEM; i++)
	{
		cached_list[i] = (cache_item*)malloc(sizeof(cache_item));
		cached_list[i]->webaddr = (char*)malloc(DEFAULT_BUFLEN);
		cached_list[i]->occupied = false;
	}

	// Initialize, create listen socket
	//listen_socket�����ڴӿͻ������յ������
	SOCKET listen_socket;
	res = initDNSServer(&listen_socket);
	if (res == 1) return 255;

	// Initialize DNSRequest Pool
	request_pool = (ReqPool*)malloc(sizeof(ReqPool) * MAX_REQ);
	memset(request_pool, 0, sizeof(ReqPool) * MAX_REQ);
	if (request_pool == NULL)
	{
		printf("malloc request_pool failed\n\n");
		exit(100);
	}
	for (int i = 0; i < MAX_REQ; i++)
	{
		request_pool[i].available = true;
	}

	//���̴߳�������
	for (int i = 0; i < MAX_THREAD; i++)
	{
		//���������������ϲ�dns��ip��ַ��listen_socket���̱߳��
		dns_consulting_threads[i] = new std::thread(CounsultThreadHandle, UPPER_DNS, listen_socket, i);
	}

	if(LEVEL != ZEROTH) printf("Initialize Complete. \n\n");

	int i = 0;

	//���ϵشӿͻ��˽������󣬲�������Ž��������
	while(1)
	{
		//ÿ5���������һ��cache�ļ�
		i++;
		char* recvbuf = (char*)malloc(DEFAULT_BUFLEN * sizeof(char));

		if (recvbuf==NULL)
		{
			printf("malloc recvbuf fail!\n\n");
			exit(100);
		}

		struct sockaddr_in clt_addr;
		int clt_addr_len = sizeof(clt_addr);
		
		memset(recvbuf, 0, sizeof(recvbuf));
		memset(&clt_addr, 0, sizeof(clt_addr));

		// Receive DNS Requests
		if (sizeof(recvbuf) <= 0)
		{
			printf("Length of recvbuf is 0!\n\n");
			exit(100);
		}
		//�ӿͻ��˽���������
		res = recvfrom(listen_socket, recvbuf, DEFAULT_BUFLEN, 0, (struct sockaddr*)&clt_addr, &clt_addr_len);
		if (res == SOCKET_ERROR)
		{
			printf("\n[error] [listen_socket]: recvfrom client error with: %d\n\n", WSAGetLastError());
		}
		//�ɹ��ӿͻ����յ����⣨DNS���ģ������������Ĵ浽recvbuf��
		else {
			//// ��ʱ���յ���������
			//if (strcmp("10.128.211.115", inet_ntoa(clt_addr.sin_addr)))
			//{

			//	printf("Receive bad message!\n\n");
			//	continue;
			//}
			//��������

			time_t timep;
			time(&timep);
			char tmp[64];
			strftime(tmp, sizeof(tmp), "%Y-%m-%d %H-%M-%S", localtime(&timep));
			if (LEVEL == SECOND)
				printf("\n[Listen_Socket]: %s\tBytes received from IP(%s): %d\n", tmp, inet_ntoa(clt_addr.sin_addr), res);

			DNSRequest* new_req = (DNSRequest*)malloc(sizeof(DNSRequest));
			memset(new_req, 0, sizeof(DNSRequest));
			if (new_req == NULL)
			{
				printf("\nmalloc new_req failed\n");
				exit(100);
			}
			//�ѱ��ģ��ֽ�������������󣨽ṹ�壩
			new_req->packet = unpackDNSPacket(recvbuf);//�ֽ���ת�ṹ��
			new_req->processed = false;//��δ����ı�־


			//�û���Ϣ���жϴӸ�ѯ�ʱ��Ĵ������ģ��Ա㷢��Ӧ���ģ�
			new_req->client_addr = clt_addr;
			new_req->client_addr_len = clt_addr_len;
			if (addDNSRequestPool(new_req) == -1)//�������
			{
				if (LEVEL == SECOND) printf("\n[Listen_Socket]: Too many requests. Ignore current one.\n");
				Sleep(1000);//�ý��̣�������̣������ߣ����������̴���һЩ֮���ټ���
			}
		}
		if (i % 5 == 0) writeCache();
		free(recvbuf);
	}//while
}

int initDNSServer(SOCKET* ret_socket)
{
	int res = 0;

	// Initalize Winsock
	WSADATA wsaData;
	res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != 0) {
		return 1;
	}

	SOCKET listen_socket = INVALID_SOCKET;

	listen_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (listen_socket == INVALID_SOCKET)
	{
		WSACleanup();
		return 1;
	}

	// �����κ�ip��ַ����53�˿ڵı���
	struct sockaddr_in hints;
	hints.sin_family = AF_INET;
	hints.sin_addr.s_addr = INADDR_ANY;//����ip
	hints.sin_port = htons(DNS_PORT);

	res = ::bind(listen_socket, (struct sockaddr*)&hints, sizeof(hints));
	if (res == SOCKET_ERROR) {
		WSACleanup();
		return 1;
	}

	*ret_socket = listen_socket;
	return 0;
}

//���ϵش�������л�ȡ������д������ز鵽�ͷ���Ӧ����ͻ��ˣ��鲻���ͷ����ϲ�dns
//listen_socket���Ƿ�������socket
//t_idΪ�̱߳�ţ��������ϲ�dns������ѯ��
void CounsultThreadHandle(const char* upper_DNS_addr, SOCKET listen_socket, int t_id)
{
	if (LEVEL == SECOND) printf("\n[Consulting Thread %d]: Created.\n", t_id);
	char* sendbuf = (char*)malloc(DEFAULT_BUFLEN);
	char* dnsbuf = (char*)malloc(DEFAULT_BUFLEN);
	int res = 0;

	//�ϲ�DNS�������ĵ�ַ
	struct sockaddr_in servaddr;
	ZeroMemory(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(DNS_PORT);
	//�ѵ��ip��ַת��Ϊ�����ֽ���ĸ�ʽ������serveraddr.sin_addr.s_addr
	inet_pton(AF_INET, upper_DNS_addr, &servaddr.sin_addr);

	//���ط�������ַ
	struct sockaddr_in myaddr;
	ZeroMemory(&myaddr, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);//ip��ַ,��ָ����������ip
	myaddr.sin_port = htons(10000 + t_id);//�˿ں�
	//ÿ���̸߳��ݲ�ͬ���̱߳�Ż�ò�ͬ�Ķ˿ں�
	//024~65535���ǲ���ϵͳ��̬����Ķ˿ںţ��ͻ��˳���Ķ˿ںţ������ɲ���ϵͳ�������Χ������ģ�
	//��TCP��UDP���׽���ͨ���У��ͻ��˵Ķ˿ںž����ڴ˷�Χ��

	//upper_dns_socket���ڸ��ϲ�dns������������
	SOCKET upper_dns_socket = socket(AF_INET, SOCK_DGRAM, 0);
	::bind(upper_dns_socket, (struct sockaddr*)&myaddr, sizeof(myaddr));
	
	//��Ӧÿ�������̴߳���һ���̴߳����ϲ�dns���ص�Ӧ��
	std::thread return_thread = std::thread(UpperThreadHandle, upper_dns_socket, listen_socket, t_id);

	while (1)
	{
		DNSRequest* req = NULL;

		while (req == NULL) {
			req = getDNSRequest();
			if (req == NULL) Sleep(20);
		}

		if (LEVEL == SECOND) printf("\n[Consulting Thread %d]: Got DNSReq %d\n", t_id, req->new_id);

		DNSPacket* recv_packet = req->packet;

		
		UINT32 ip_addr = 0;
		//ֻ�����һ��ѯ��
		//�ڱ����ļ���host��cache���в��Ҹ�������ip_addr�����ҵ���ip��ַ����������ֵΪ�������ͣ�cached��blocked��notfound��
		ADDR_TYPE addr_type = getAddrType(recv_packet->p_qpointer[0]->q_qname, &ip_addr, t_id, req);
		//printf("[Consulting Thread %d]:Search type finished, type: %d\n\n", t_id, addr_type);

		switch (addr_type)
		{
		//blocked����cached��ִ���������
		//ֱ�Ӹ��ͻ��˷��أ�������ѯ�ϲ�dns
		case BLOCKED:
		case CACHED:
		{
			// ����ip��ַ���ɷ��ؿͻ��˵��ֽ���
			int sendbuflen;
			//��ȡ�ش�ı��������ú��������blocked����cached������ͬ�ı���
			//blocked���ص�����Ч�ı��ģ�����
			sendbuf = getDNSResult(recv_packet, req->old_id, ip_addr, addr_type, &sendbuflen);
			if (LEVEL == SECOND) printf("\n[Consulting Thread %d]: Start sending result to client\n", t_id);

			//�𸴱��ķ��ظ��ͻ���
			res = sendto(listen_socket, sendbuf, sendbuflen, 0, (struct sockaddr*)&(req->client_addr), req->client_addr_len);
			char* client_ipaddr = inet_ntoa(req->client_addr.sin_addr);
			if (res == SOCKET_ERROR)
				printf("\n[error] [Consulting Thread %d]: sendto() failed with error code : %d\n", t_id, WSAGetLastError());
			else
				if (LEVEL == SECOND) printf("\n[Consulting Thread %d]: Answer back to client(%s)\n", t_id, client_ipaddr);
			//��������ϣ���������
			finishDNSRequest(req->new_id);
			if (sendbuf) free(sendbuf);
		}
		break;
		case ADDR_NOT_FOUND:
		{
			int packet_length;
			ushort p_id = req->new_id;
			//��ѯ�ʱ��ĵ�id��Ϊ�·����id������ͬʱ��ѯ��id��ͬ�������⣩
			recv_packet->p_header->h_id = p_id;
			//�ѽṹ��ת��Ϊ���������Ա㷢���ϲ�dns��������ѯ
			char* send_string = packDNSPacket(recv_packet, &packet_length);

			if (LEVEL == SECOND) printf("\n[Consulting Thread %d] [NOT FOUND]: Start consulting Upper DNS(%s)\n", t_id, upper_DNS_addr);
			//������ͨ��upper-dns-socket���͸��ϲ�dns������
			if (sendto(upper_dns_socket, send_string, packet_length, 0, (struct sockaddr*)&servaddr, sizeof(servaddr)) == SOCKET_ERROR)
				printf("\n[Consulting Thread %d]: sendto() failed with error code : %d\n", t_id, WSAGetLastError());
			if (send_string) free(send_string);
		}
		break;
		}
	}
	if (sendbuf) free(sendbuf);
	if (dnsbuf) free(dnsbuf);
}

//��Ӧÿ�������̴߳���һ���̴߳����ϲ�dns���ص�Ӧ�𣬽��и��´������ظ��ͻ���
void UpperThreadHandle(SOCKET upper_dns_socket, SOCKET listen_socket, int t_id)
{
	int res = 0;
	int sleeptime = 20;
	struct sockaddr_in servaddr;
	int servaddrlen = sizeof(servaddr);
	char* dnsbuf = (char*)malloc(DEFAULT_BUFLEN);
	while (1)
	{
		//���յ����ϲ�dns�����Ĵ𸴱��ģ�����dnsbuf
		res = recvfrom(upper_dns_socket, dnsbuf, DEFAULT_BUFLEN, 0, (struct sockaddr*)&servaddr, &servaddrlen);
		/*
		 * WSAEWOULDBLOCK��������ջ��߷��͵�BUFFER����
		 * Ҫ�ȴ�һ����ܽ��գ���û�з�������
		 * ELSE�����ݹ����з����˴���
		 */
		if (res == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAEWOULDBLOCK)
			{
				Sleep(sleeptime);
				continue;
			}
			else
			{
				printf("\n[UPPER Thread %d]:! recvfrom_server() failed with error code : %d\n", t_id, WSAGetLastError());
				break;
			}
		}
		else
		{
			if (LEVEL == SECOND) printf("\n[UPPER Thread %d]: Bytes received from DNS_SERVER\n", t_id);

			// �õ�new_id��the i_th pool��
			int p_id = ntohs(*(ushort*)dnsbuf);

			//����������Ѳ���������У���������/�����ˣ�
			if (request_pool[p_id].available == true)
			{
				continue;//��������ѭ����������ǰ���ģ�
			}
			//��ǰ����װ��ṹ��
			DNSPacket* return_pack = unpackDNSPacket(dnsbuf);

			// ��ȡ�ñ��ĵ�ip����������Ϣ�Դ���cached_list��
			if (return_pack->p_rpointer[0]->r_rdata != NULL && return_pack->p_qpointer[0]->q_qtype == 1)
			{
				UINT32* rdata_pointer = (UINT32*)return_pack->p_rpointer[0]->r_rdata;
				//ip_uintΪrdata����32λ����ip�ĵ�ַ��
				UINT32 ip_uint = (*rdata_pointer);
				in_addr inaddr;
				inaddr.S_un.S_addr = ip_uint;
				char* ipaddr = inet_ntoa(inaddr);
				char* webaddr = (char*)malloc(DEFAULT_BUFLEN);

				strcpy(webaddr, return_pack->p_qpointer[0]->q_qname);

				// �����ɼ����ַ�ת��Ϊ.����Ա�
				for (int i = 0; i < strlen(webaddr); i++)
				{
					if (webaddr[i] < 0x20)
						webaddr[i] = '.';
					else if (webaddr[i] >= 'A' && webaddr[i] <= 'Z')
					{
						webaddr[i] -= 'A' - 'a';
					}
				}
				if (LEVEL == SECOND) printf("\n[UPPER Thread %d]:Domain: %s, IP: %s saved in CACHE\n", t_id, webaddr+1, ipaddr);

				cache_mutex.lock();
				
				for (int i = 0; i < MAX_CACHED_ITEM; i++)
				{
					if (cached_list[i]->occupied)
					{
						continue;
					}
					cached_list[i]->occupied = true;
					cached_list[i]->ttl = MAX_CACHE_TTL;
					inet_pton(AF_INET, ipaddr, &cached_list[i]->ip_addr);
					strcpy(cached_list[i]->webaddr, webaddr + 1);
					break;
				}
				if (webaddr) free(webaddr);
				cache_mutex.unlock();
			}
			//�����������
			DNSRequest* req = finishDNSRequest(p_id);
			//��id��Ϊԭ����id
			*(ushort*)dnsbuf = htons(req->old_id);

			// �𸴱��ķ��ظ��ͻ���
			res = sendto(listen_socket, dnsbuf, DEFAULT_BUFLEN, 0, (struct sockaddr*)&(req->client_addr), req->client_addr_len);
			char* client_ipaddr = inet_ntoa(req->client_addr.sin_addr);
			if (res == SOCKET_ERROR)
				printf("\n[UPPER Thread %d]:sendto() failed with error code : %d\n", t_id, WSAGetLastError());
			else
			{
				if (LEVEL == SECOND) printf("\n[UPPER Thread %d]:Answer back to client(%s)\n", t_id, client_ipaddr);
			}
		}

	}
	if (dnsbuf) free(dnsbuf);
}



