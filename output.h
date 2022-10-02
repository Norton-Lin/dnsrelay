/**
 * @file output.h
 * @author Linzhi LiZhichao LiuXiao
 * @brief 输出函数定义
 * @version 0.1
 * @date 2022-07-02
 * 
 * @copyright BUPT (c) 2022
 * 
 */
#ifndef OUTPUT_H
#define OUTPUT_H
#include "head.h"
void printHex(const unsigned char *buf, size_t len);                                                 //输出指定长度缓冲区信息
void printResourceRecord(Resource *r);                                                               //输出资源记录信息
void printDatagram(Message *message);                                                                //输出数据报信息
void printInfo();                                                                                    //打印程序基本信息
/**
 * @brief 输出指定长度缓冲区信息
 * @param buf 缓冲区指针
 * @param len 指定长度
 */
void printHex(const unsigned char *buf, size_t len)
{
    int i;
    printf("%zu bytes:\n", len);//输出size_t型
    for (i = 0; i < len; ++i)
    {
        printf("%02x ", buf[i]);//输出十六进制数
        if ((i % 16) == 15)
            printf("\n");
    }
    printf("\n");
}
/**
 * @brief 输出资源记录
 * @param r 资源记录指针
 */
void printResourceRecord(Resource *r)
{
    while (r)//遍历资源记录区
    {
        printf("  ResourceRecord { name '%s', type %u, class %u, ttl %u, rdLength %u, ",
               r->name,
               r->type,
               r->class,
               r->ttl,
               r->rdLength);//输出应答报文基本信息

        Data *rd = &r->rd_data;
        //分类型输出数据段信息
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
 * @brief 输出数据报信息
 * @param message 数据报指针
 */
void print_query(Message *message)
{
    Question *q;
    printf("QUERY { ID: %02x", message->id);
    printf(". FLAGS: [ QR: %u, OpCode: %u ]", message->qr, message->opcode);
    printf(", QDcount: %u", message->qdCount);
    printf(", ANcount: %u", message->anCount);
    printf(", NScount: %u", message->nsCount);
    printf(", ARcount: %u,\n", message->arCount);//输出数据报基本信息

    q = message->questions;
    while (q)//遍历查询报文
    {
        printf("\tQuestion { qName '%s', qType %u, qClass %u }\n",
               q->qName,
               q->qType,
               q->qClass);
        q = q->next;
    }
    //输出资源区信息
    printResourceRecord(message->answers);
    printResourceRecord(message->authorities);
    printResourceRecord(message->additionals);
    printf("}\n");
}

/**
 * @brief 打印程序基本信息
 */
void printInfo()
{
    printf("---------------------------------------------------------------------------\n");
    printf("DNS中继服务器 \n");
    printf("@Author: 林志\t李智超\t刘霄\n");
    printf("@Teacher: 高占春\n");
    printf("@Version: 1.0.0\n");
    printf("@Copyright: BUPT\n");
    printf("@Usage: [] , [-d server file] , [-dd server] \n");
    printf("---------------------------------------------------------------------------\n");
}

#endif