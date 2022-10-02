/**
 * @file output.h
 * @author Linzhi LiZhichao LiuXiao
 * @brief �����������
 * @version 0.1
 * @date 2022-07-02
 * 
 * @copyright BUPT (c) 2022
 * 
 */
#ifndef OUTPUT_H
#define OUTPUT_H
#include "head.h"
void printHex(const unsigned char *buf, size_t len);                                                 //���ָ�����Ȼ�������Ϣ
void printResourceRecord(Resource *r);                                                               //�����Դ��¼��Ϣ
void printDatagram(Message *message);                                                                //������ݱ���Ϣ
void printInfo();                                                                                    //��ӡ���������Ϣ
/**
 * @brief ���ָ�����Ȼ�������Ϣ
 * @param buf ������ָ��
 * @param len ָ������
 */
void printHex(const unsigned char *buf, size_t len)
{
    int i;
    printf("%zu bytes:\n", len);//���size_t��
    for (i = 0; i < len; ++i)
    {
        printf("%02x ", buf[i]);//���ʮ��������
        if ((i % 16) == 15)
            printf("\n");
    }
    printf("\n");
}
/**
 * @brief �����Դ��¼
 * @param r ��Դ��¼ָ��
 */
void printResourceRecord(Resource *r)
{
    while (r)//������Դ��¼��
    {
        printf("  ResourceRecord { name '%s', type %u, class %u, ttl %u, rdLength %u, ",
               r->name,
               r->type,
               r->class,
               r->ttl,
               r->rdLength);//���Ӧ���Ļ�����Ϣ

        Data *rd = &r->rd_data;
        //������������ݶ���Ϣ
        switch (r->type)
        {
        case Type_A:
            printf("Address Resource Record { address ");

            for (int i = 0; i < 4; ++i)
                printf("%s%u", (i ? "." : ""), rd->recordA.addr[i]);

            printf(" }");
            break;
        case Type_NS:
            printf("Name Server Resource Record { name %s }",
                   rd->recordNS.name);
            break;
        case Type_CNAME:
            printf("Canonical Name Resource Record { name %s }",
                   rd->recordCNAME.name);
            break;
        case Type_SOA:
            printf("SOA { MName '%s', RName '%s', serial %u, refresh %u, retry %u, expire %u, minimum %u }",
                   rd->recordSOA.MName,
                   rd->recordSOA.RName,
                   rd->recordSOA.serial,
                   rd->recordSOA.refresh,
                   rd->recordSOA.retry,
                   rd->recordSOA.expire,
                   rd->recordSOA.minimum);
            break;
        case Type_PTR:
            printf("Pointer Resource Record { name '%s' }",
                   rd->recordPTR.name);
            break;
        case Type_MX:
            printf("Mail Exchange Record { preference %u, exchange '%s' }",
                   rd->recordMX.preference,
                   rd->recordMX.exchange);
            break;
        case Type_TXT:
            printf("Text Resource Record { txt_data '%s' }",
                   rd->recordTXT.data);
            break;
        case Type_AAAA:
            printf("AAAA Resource Record { address ");

            for (int i = 0; i < 16; ++i)
                printf("%s%02x", (i ? ":" : ""), rd->recordAAAA.addr[i]);

            printf(" }");
            break;
        default:
            printf("Unknown Resource Record { ??? }");
        }
        printf("}\n");
        r = r->next;
    }
}

/**
 * @brief ������ݱ���Ϣ
 * @param message ���ݱ�ָ��
 */
void print_query(Message *message)
{
    Question *q;
    printf("QUERY { ID: %02x", message->id);
    printf(". FLAGS: [ QR: %u, OpCode: %u ]", message->qr, message->opcode);
    printf(", QDcount: %u", message->qdCount);
    printf(", ANcount: %u", message->anCount);
    printf(", NScount: %u", message->nsCount);
    printf(", ARcount: %u,\n", message->arCount);//������ݱ�������Ϣ

    q = message->questions;
    while (q)//������ѯ����
    {
        printf("\tQuestion { qName '%s', qType %u, qClass %u }\n",
               q->qName,
               q->qType,
               q->qClass);
        q = q->next;
    }
    //�����Դ����Ϣ
    printResourceRecord(message->answers);
    printResourceRecord(message->authorities);
    printResourceRecord(message->additionals);
    printf("}\n");
}

/**
 * @brief ��ӡ���������Ϣ
 */
void printInfo()
{
    printf("---------------------------------------------------------------------------\n");
    printf("DNS�м̷����� \n");
    printf("@Author: ��־\t���ǳ�\t����\n");
    printf("@Teacher: ��ռ��\n");
    printf("@Version: 1.0.0\n");
    printf("@Copyright: BUPT\n");
    printf("@Usage: [] , [-d server file] , [-dd server] \n");
    printf("---------------------------------------------------------------------------\n");
}

#endif