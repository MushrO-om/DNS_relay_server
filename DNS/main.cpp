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
	getParameter(argc, argv);//获取运行参数
	if (LEVEL != ZEROTH) {
		printf("Designed by Lan Xuechao & Chen Lianjie\n");
		printf("The IP of uppperDNS is [%s]\n", UPPER_DNS);
		printf("The path of local host file is [%s]\n", HOST_FILE_LOC);
	}
	dnsRelay();
	return 0;
}

void getParameter(int argc, char** argv)//获取运行参数
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
	//listen_socket是用于从客户端那收到请求的
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

	//多线程处理请求
	for (int i = 0; i < MAX_THREAD; i++)
	{
		//传入三个参数，上层dns的ip地址，listen_socket和线程编号
		dns_consulting_threads[i] = new std::thread(CounsultThreadHandle, UPPER_DNS, listen_socket, i);
	}

	if(LEVEL != ZEROTH) printf("Initialize Complete. \n\n");

	int i = 0;

	//不断地从客户端接受请求，并把请求放进请求池中
	while(1)
	{
		//每5个请求更新一次cache文件
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
		//从客户端接收请求报文
		res = recvfrom(listen_socket, recvbuf, DEFAULT_BUFLEN, 0, (struct sockaddr*)&clt_addr, &clt_addr_len);
		if (res == SOCKET_ERROR)
		{
			printf("\n[error] [listen_socket]: recvfrom client error with: %d\n\n", WSAGetLastError());
		}
		//成功从客户端收到问题（DNS报文），把整个报文存到recvbuf中
		else {
			//// 有时会收到垃圾报文
			//if (strcmp("10.128.211.115", inet_ntoa(clt_addr.sin_addr)))
			//{

			//	printf("Receive bad message!\n\n");
			//	continue;
			//}
			//创建请求

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
			//把报文（字节流）打包进请求（结构体）
			new_req->packet = unpackDNSPacket(recvbuf);//字节流转结构体
			new_req->processed = false;//尚未处理的标志


			//用户信息（判断从该询问报文从哪来的，以便发回应答报文）
			new_req->client_addr = clt_addr;
			new_req->client_addr_len = clt_addr_len;
			if (addDNSRequestPool(new_req) == -1)//请求池满
			{
				if (LEVEL == SECOND) printf("\n[Listen_Socket]: Too many requests. Ignore current one.\n");
				Sleep(1000);//该进程（请求进程）先休眠，等其他进程处理一些之后再继续
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

	// 接受任何ip地址发到53端口的报文
	struct sockaddr_in hints;
	hints.sin_family = AF_INET;
	hints.sin_addr.s_addr = INADDR_ANY;//本地ip
	hints.sin_port = htons(DNS_PORT);

	res = ::bind(listen_socket, (struct sockaddr*)&hints, sizeof(hints));
	if (res == SOCKET_ERROR) {
		WSACleanup();
		return 1;
	}

	*ret_socket = listen_socket;
	return 0;
}

//不断地从请求池中获取请求进行处理，本地查到就发回应答给客户端，查不到就发给上层dns
//listen_socket就是服务器的socket
//t_id为线程编号，用于向上层dns服务器询问
void CounsultThreadHandle(const char* upper_DNS_addr, SOCKET listen_socket, int t_id)
{
	if (LEVEL == SECOND) printf("\n[Consulting Thread %d]: Created.\n", t_id);
	char* sendbuf = (char*)malloc(DEFAULT_BUFLEN);
	char* dnsbuf = (char*)malloc(DEFAULT_BUFLEN);
	int res = 0;

	//上层DNS服务器的地址
	struct sockaddr_in servaddr;
	ZeroMemory(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(DNS_PORT);
	//把点分ip地址转化为网络字节序的格式，存入serveraddr.sin_addr.s_addr
	inet_pton(AF_INET, upper_DNS_addr, &servaddr.sin_addr);

	//本地服务器地址
	struct sockaddr_in myaddr;
	ZeroMemory(&myaddr, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);//ip地址,泛指本机的所有ip
	myaddr.sin_port = htons(10000 + t_id);//端口号
	//每个线程根据不同的线程编号获得不同的端口号
	//024~65535：是操作系统动态分配的端口号，客户端程序的端口号，就是由操作系统从这个范围来分配的，
	//在TCP与UDP的套接字通信中，客户端的端口号就是在此范围中

	//upper_dns_socket用于给上层dns服务器发报文
	SOCKET upper_dns_socket = socket(AF_INET, SOCK_DGRAM, 0);
	::bind(upper_dns_socket, (struct sockaddr*)&myaddr, sizeof(myaddr));
	
	//对应每个处理线程创建一个线程处理上层dns发回的应答
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
		//只处理第一个询问
		//在本地文件（host、cache）中查找该域名，ip_addr返回找到的ip地址，函数返回值为查找类型（cached、blocked、notfound）
		ADDR_TYPE addr_type = getAddrType(recv_packet->p_qpointer[0]->q_qname, &ip_addr, t_id, req);
		//printf("[Consulting Thread %d]:Search type finished, type: %d\n\n", t_id, addr_type);

		switch (addr_type)
		{
		//blocked或是cached都执行下面这段
		//直接给客户端发回，不用咨询上层dns
		case BLOCKED:
		case CACHED:
		{
			// 根据ip地址生成发回客户端的字节流
			int sendbuflen;
			//获取回答的报文流，该函数会根据blocked还是cached产生不同的报文
			//blocked返回的是无效的报文（错误）
			sendbuf = getDNSResult(recv_packet, req->old_id, ip_addr, addr_type, &sendbuflen);
			if (LEVEL == SECOND) printf("\n[Consulting Thread %d]: Start sending result to client\n", t_id);

			//答复报文发回给客户端
			res = sendto(listen_socket, sendbuf, sendbuflen, 0, (struct sockaddr*)&(req->client_addr), req->client_addr_len);
			char* client_ipaddr = inet_ntoa(req->client_addr.sin_addr);
			if (res == SOCKET_ERROR)
				printf("\n[error] [Consulting Thread %d]: sendto() failed with error code : %d\n", t_id, WSAGetLastError());
			else
				if (LEVEL == SECOND) printf("\n[Consulting Thread %d]: Answer back to client(%s)\n", t_id, client_ipaddr);
			//请求处理完毕，丢弃请求
			finishDNSRequest(req->new_id);
			if (sendbuf) free(sendbuf);
		}
		break;
		case ADDR_NOT_FOUND:
		{
			int packet_length;
			ushort p_id = req->new_id;
			//把询问报文的id改为新分配的id（以免同时查询的id相同产生问题）
			recv_packet->p_header->h_id = p_id;
			//把结构体转化为报文流，以便发给上层dns服务器查询
			char* send_string = packDNSPacket(recv_packet, &packet_length);

			if (LEVEL == SECOND) printf("\n[Consulting Thread %d] [NOT FOUND]: Start consulting Upper DNS(%s)\n", t_id, upper_DNS_addr);
			//报文流通过upper-dns-socket发送给上层dns服务器
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

//对应每个处理线程创建一个线程处理上层dns发回的应答，进行更新处理，发回给客户端
void UpperThreadHandle(SOCKET upper_dns_socket, SOCKET listen_socket, int t_id)
{
	int res = 0;
	int sleeptime = 20;
	struct sockaddr_in servaddr;
	int servaddrlen = sizeof(servaddr);
	char* dnsbuf = (char*)malloc(DEFAULT_BUFLEN);
	while (1)
	{
		//接收到从上层dns发来的答复报文，存入dnsbuf
		res = recvfrom(upper_dns_socket, dnsbuf, DEFAULT_BUFLEN, 0, (struct sockaddr*)&servaddr, &servaddrlen);
		/*
		 * WSAEWOULDBLOCK：代表接收或者发送的BUFFER满了
		 * 要等待一会才能接收，并没有发生错误
		 * ELSE：传递过程中发生了错误
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

			// 得到new_id（the i_th pool）
			int p_id = ntohs(*(ushort*)dnsbuf);

			//如果该请求已不在请求池中（处理完了/丢弃了）
			if (request_pool[p_id].available == true)
			{
				continue;//跳过本次循环（跳过当前报文）
			}
			//当前报文装入结构体
			DNSPacket* return_pack = unpackDNSPacket(dnsbuf);

			// 获取该报文的ip和域名等信息以存入cached_list中
			if (return_pack->p_rpointer[0]->r_rdata != NULL && return_pack->p_qpointer[0]->q_qtype == 1)
			{
				UINT32* rdata_pointer = (UINT32*)return_pack->p_rpointer[0]->r_rdata;
				//ip_uint为rdata的首32位（即ip的地址）
				UINT32 ip_uint = (*rdata_pointer);
				in_addr inaddr;
				inaddr.S_un.S_addr = ip_uint;
				char* ipaddr = inet_ntoa(inaddr);
				char* webaddr = (char*)malloc(DEFAULT_BUFLEN);

				strcpy(webaddr, return_pack->p_qpointer[0]->q_qname);

				// 将不可见的字符转化为.方便对比
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
			//该请求处理完成
			DNSRequest* req = finishDNSRequest(p_id);
			//把id改为原来的id
			*(ushort*)dnsbuf = htons(req->old_id);

			// 答复报文发回给客户端
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



