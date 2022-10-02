/**
 * @file head.h
 * @author Linzhi LiZhichao LiuXiao
 * @brief 报文结构体相关定义与常量定义
 * @version 0.1
 * @date 2022-07-02
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef HEAD_H
#define HEAD_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <WinSock2.h>
#include <windows.h>
#include <getopt.h>
#include "trie.h"
#include "util.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define ID_TABLE_SIZE 1024
#define ID_EXPIRE_TIME 4 // 4s
#define SELECT_MODE 1//选择模式
#define NONBLOCK_MODE 2//非阻塞模式
#define MODE 1
char DNS_SERVER[16] = "10.3.9.44"; // 指定DNS服务器，默认采用电脑自带DNS"218.85.157.99"
char CONFIG_FILE[100] = "./dnsrelay.txt";//指定配置文件
int PORT = 53;
int LEVEL = 0;//调试等级
/**
 * @brief 通信变量
 */
WSADATA wsaData;
SOCKET clientSocket;
SOCKET serverSocket;
struct sockaddr_in clientAddr;
struct sockaddr_in serverAddr;
int addr_len = sizeof(struct sockaddr_in);
int requstCount = 0;
/**
 * @brief 掩码常量，用于头部标志的置位
 */
static const unsigned int QR_MASK = 0x8000;
static const unsigned int OPCODE_MASK = 0x7800;
static const unsigned int AA_MASK = 0x0400;
static const unsigned int TC_MASK = 0x0200;
static const unsigned int RD_MASK = 0x0100;
static const unsigned int RA_MASK = 0x8000;
static const unsigned int RCODE_MASK = 0x000F;
/**
 * @brief RCODE字段
 */
enum RCODE
{
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NOtImp = 4,
    Refused = 5
};

/**
 * @brief 资源类型
 */
enum ResourceType
{
    Type_A = 1,
    Type_NS = 2,
    Type_CNAME = 5,
    Type_SOA = 6,
    Type_PTR = 12,
    Type_MX = 15,
    Type_TXT = 16,
    Type_AAAA = 28
};

/**
 * @brief 查询报文
 * 
 */
typedef struct Questions
{
    char *qName; //查询名
    unsigned short qType;//查询类型
    unsigned short qClass;//查询列
    struct Questions *next; // 链表
} Question;

/**
 * @brief 报文数据端
 */
typedef union ResourceData
{
    struct
    {
        unsigned char addr[4];
    } recordA;//A记录类型
    struct
    {
        char *name;
    } recordNS;//NS记录类型
    struct
    {
        char *name;
    } recordCNAME;//CANAME类型
    struct
    {
        char *MName;
        char *RName;
        unsigned int serial;
        unsigned int refresh;
        unsigned int retry;
        unsigned int expire;
        unsigned int minimum;
    } recordSOA;//SOA类型
    struct
    {
        char *name;
    } recordPTR;//PTR类型
    struct
    {
        unsigned short preference;
        char *exchange;
    } recordMX;//MX类型
    struct
    {
        unsigned char dataLength;
        char *data;
    } recordTXT;//TXT类型
    struct
    {
        unsigned char addr[16];
    } recordAAAA;//aaaa类型
} Data;

// Resource Record Format
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                                               /
// /                      NAME                     /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TTL                      |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   RDLENGTH                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                     RDATA                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/**
 * @brief 资源记录定义报文
 */
typedef struct ResourceRecord
{
    char *name;//名称
    unsigned short type;//类型码
    unsigned short class;//类
    unsigned int ttl;//生存周期
    unsigned short rdLength;//资源数据长度
    Data rd_data;//数据段
    struct ResourceRecord *next; // 链表
} Resource;
// DNS Messages
// +---------------------+
// |        Header       |  固定长度的Header部分
// +---------------------+
// |       Question      | the question for the name server
// +---------------------+
// |        Answer       | RRs answering the question
// +---------------------+
// |      Authority      | RRs pointing toward an authority
// +---------------------+
// |      Additional     | RRs holding additional information
// +---------------------+

// Header Section Format
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       | 由客户程序设置并由服务器返回结果。客户程序通过它来确定响应与查询是否匹配
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   | 标志位
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
typedef struct Messages
{
    unsigned short id; // ID字段 
    // 标志位
    unsigned short qr;     // 查询/响应
    unsigned short opcode; // 操作码 
    unsigned short aa;     // 权威答案
    unsigned short tc;     // 截断标志 
    unsigned short rd;     // 期望递归 
    unsigned short ra;     // 递归可用 
    unsigned short rcode;  // 响应码 

    unsigned short qdCount; // 问题数 
    unsigned short anCount; // 回答部分的RRs数 
    unsigned short nsCount; // 名称服务器中RRs的数量
    unsigned short arCount; // 附加记录部分中的RRs数 
    Question *questions;//查询报文指针
    Resource *answers;//三种不同资源报文指针
    Resource *authorities;
    Resource *additionals;
} Message;

typedef struct {
    unsigned short clientId;//客户端ID
    int expireTime; // time IdConversion expired过期时间
    struct sockaddr_in clientAddr;//客户端网络通信地址
} IdConversion;//ID转换表

IdConversion IdTable[ID_TABLE_SIZE]; // 声明ID转换表

#endif 