#pragma once
#include "request_pool.h"

extern ReqPool* request_pool;
extern std::mutex id_mutex, pool_mutex, req_counter_mutex;

extern const char* UPPER_DNS;
extern const char* HOST_FILE_LOC;
extern cmdLevel LEVEL;

//�Ѵ��ڸ������е�������ȡ�����ô��������µ�����
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

//��������л�ȡ��һ���������û�����󷵻�null
DNSRequest* getDNSRequest()
{
	DNSRequest* req = NULL;
	if (pool_mutex.try_lock())
	{
		for (int i = 0; i < MAX_REQ; i++)
		{
			//�������������
			if (request_pool[i].available == false)
			{
				
				//δ��ĳ���̴߳���
				if (request_pool[i].req->processed == false)
				{
					//�����������������ڴ��ڵ�ʱ�䳬�����������ڣ�����ʱ��δ������Ӧ�ö���������
					if (difftime(time(NULL), request_pool[i].startTime) > MAX_REQ_TTL)
					{
						finishDNSRequest(i);
						continue;
					}
					req = request_pool[i].req;
					//���Ϊ�Ѵ���
					request_pool[i].req->processed = true;
					break;
				}
			}
		}
		pool_mutex.unlock();
	}
	return req;
}

//�������������أ���������������е��±꣨�������޷����뷵��-1��
int addDNSRequestPool(DNSRequest* req)
{
	std::lock_guard<std::mutex> pool_guard(pool_mutex);
	for (int i = 0; i < MAX_REQ; i++)
	{
		if (request_pool[i].available)
		{
			//��Ǹ�������ѱ�ռ��
			request_pool[i].available = false;
			//����ľ�id��Ϊѯ�ʱ��ĵ�id
			req->old_id = req->packet->p_header->h_id;
			//����������µ�id����Ϊ������е��±�
			req->new_id = i;
			//�ͷ�ԭ����
			free_req(request_pool[i].req);
			//����������
			request_pool[i].req = req;
			//��¼�����������صĿ�ʼʱ��
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