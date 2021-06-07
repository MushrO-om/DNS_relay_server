#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include "header.h"

extern const char* UPPER_DNS;
extern const char* HOST_FILE_LOC;
extern cmdLevel LEVEL;

/**
 *		��srcָ���char*ת��ΪDNSHeader
 * 
 *		src Դָ��
 *		ret_prt ����ָ��
 * 
 *		Header���ȹ̶�Ϊ12 Bytes
 *		��������ʱret_ptr���޸�ΪDNSHeader����һ����ַ
 *		src���ᱻ�޸�
 */
DNSHeader* fromDNSHeader(char* src, char** ret_ptr);

/**
 *		��srcָ���char*ת��ΪDNSQuery

 *		src Դָ��
 *		ret_prt ����ָ��
 * 
 *		��������ʱret_ptr���޸�ΪDNSQuery����һ����ַ
 *		src���ᱻ�޸�
 */
DNSQuery* fromDNSQuery(char* src, char** ret_ptr);

/**
 *		��srcָ���char*ת��ΪDNSResponse
 * 
 *		src Դָ��
 *		head DNS���ĵ�ͷָ��
 *		ret_prt ����ָ��
 * 
 *		��������ʱret_ptr���޸�ΪDNSReponse����һ����ַ
 *		src���ᱻ�޸�
 */
DNSResponse* fromDNSResponse(char* src, char* head, char** ret_ptr);

/**
 *		��DNSHeader*ָ�������ת��Ϊ����������ֽ���
 * 
 *		DNSHeader* Դָ��
 * 
 *		flags���ֵĴ�СΪ2 Bytes�������˰�λ��(&)������λ(<<)�ķ�������
 *		ret_s�����շ��ص�ָ��
 *		tmp_s��ʵ�ʽ����ֶβ�����ָ��
 */
char* toDNSHeader(DNSHeader*);

/**
 *		��DNSQueryr*ָ�������ת��Ϊ����������ֽ���
 * 
 *		DNSQueryr* Դָ��
 *		char *
 * 
 *		tmp_u_short_pointer��tmp_char_pointerָ���������ͬ��ֻ����ָ��ķ�Χ��ͬ(2bytes �� 1bytes)
 *		qname�ĳ��Ȳ���ȷ����������'\0'��β����Ҫʹ��strlen��ȡ
 */
char* toDNSQuery(DNSQuery*);

/**
 *		��DNSResponse*ָ�������ת��Ϊ����������ֽ���
 * 
 *		DNSResponse* Դָ��
 *		char *
 * 
 *		ʹ�÷�����toDNSQuery()��ͬ
 */
char* toDNSResponse(DNSResponse*);

/**
 *		������������ֽ���ָ�������ת��ΪDNSPacket
 * 
 *		char* Դָ��
 * 
 *		����������fromDNSHeader()��fromDNSQuery()��fromDNSResponse()
 *		����DNS���ĸ�ʽ����ת��
 *		����ʵ����Ҫ����������Query��Response����ת����ֻ�ֱ�Ե�һ������ת��
 */
DNSPacket* unpackDNSPacket(char*);

/**
 *		��DNSPacket*ָ�������ת��Ϊ����������ֽ���
 * 
 *		DNSPacket* Դָ��
 *		int& �ֽ�������

 *		unpackDNSPacket�������
 */
char* packDNSPacket(DNSPacket*, int*);