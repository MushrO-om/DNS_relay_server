#pragma once
#include "request_pool.h"

extern ReqPool* request_pool;
extern std::mutex id_mutex, pool_mutex, req_counter_mutex;

extern const char* UPPER_DNS;
extern const char* HOST_FILE_LOC;
extern cmdLevel LEVEL;

//把存在该请求中的请求报文取出，该处可填入新的请求
DNSRequest* finishDNSRequest(int new_id)
{
	DNSRequest* req = NULL;
	if(pool_mutex.try_lock()) {
		req = request_pool[new_id].req;
		request_pool[new_id].available = true;
		if(request_pool[new_id].req) request_pool[new_id].req->processed = false;
		pool_mutex.unlock();
	}
	return req;
}

//从请求池中获取第一个请求，如果没有请求返回null
DNSRequest* getDNSRequest()
{
	DNSRequest* req = NULL;
	if (pool_mutex.try_lock())
	{
		for (int i = 0; i < MAX_REQ; i++)
		{
			//该请求池有请求
			if (request_pool[i].available == false)
			{
				
				//未被某个线程处理
				if (request_pool[i].req->processed == false)
				{
					//如果该请求在请求池内存在的时间超过了生存周期（即超时仍未处理，就应该丢弃该请求）
					if (difftime(time(NULL), request_pool[i].startTime) > MAX_REQ_TTL)
					{
						finishDNSRequest(i);
						continue;
					}
					req = request_pool[i].req;
					//标记为已处理
					request_pool[i].req->processed = true;
					break;
				}
			}
		}
		pool_mutex.unlock();
	}
	return req;
}

//把请求加入请求池，返回其在请求池中的下标（池子满无法加入返回-1）
int addDNSRequestPool(DNSRequest* req)
{
	std::lock_guard<std::mutex> pool_guard(pool_mutex);
	for (int i = 0; i < MAX_REQ; i++)
	{
		if (request_pool[i].available)
		{
			//标记该请求坑已被占用
			request_pool[i].available = false;
			//请求的旧id即为询问报文的id
			req->old_id = req->packet->p_header->h_id;
			//给请求分配新的id，即为请求池中的下标
			req->new_id = i;
			//释放原请求
			free_req(request_pool[i].req);
			//加入新请求
			request_pool[i].req = req;
			//记录请求进入请求池的开始时间
			request_pool[i].startTime = time(NULL);
			return i;
		}
	}
	return -1;
}

void free_req(DNSRequest* req) {
	if(req) {
		if (req->packet) {
			if (req->packet->p_header) free(req->packet->p_header);
			for (int i = 0; i < 50; i++) {
				if (req->packet->p_qpointer[i]) {
					if (req->packet->p_qpointer[i]->q_qname) free(req->packet->p_qpointer[i]->q_qname);
					free(req->packet->p_qpointer[i]);
				}
				if (req->packet->p_rpointer[i]) {
					if (req->packet->p_rpointer[i]->r_name) free(req->packet->p_rpointer[i]->r_name);
					if (req->packet->p_rpointer[i]->r_rdata) free(req->packet->p_rpointer[i]->r_rdata);
					free(req->packet->p_rpointer[i]);
				}
			}
			free(req->packet);
		}
		free(req);
	}
}