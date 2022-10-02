/**
 * @file communicate.h
 * @author Linzhi LiZhichao LiuXiao
 * @brief 通信相关函数操作
 * @version 0.1
 * @date 2022-07-02
 * 
 * @copyright BUPT (c) 2022
 * 
 */
#ifndef COMMUN_H
#define COMMUN_H
#include"head.h"
bool isExpired(IdConversion idc);                                             //判断ID转换表是否到期
unsigned short newId(unsigned short clientId, struct sockaddr_in clientAddr); //建立新的ID转换表
void receiveFromClient();                                                     //从客户端接收数据
void receiveFromServer();                                                     //从服务器接收数据
void initSocket();                                                            //初始化套接字
/**
 * @brief 判断ID转换表是否到期
 * @param idc ID转换表
 * @return bool true未过期 false过期
 */
bool isExpired(IdConversion idc)
{
    return idc.expireTime < time(NULL); //与当前系统时间进行比较，判断是否过期
}

/**
 * @brief 建立新的ID转换表
 *
 * @param clientId 客户端ID
 * @param clientAddr 客户端网络通信地址
 * @return unsigned short 新的ID转换表大小
 */
unsigned short newId(unsigned short clientId, struct sockaddr_in clientAddr)
{
    unsigned short i;
    for (i = 0; i < ID_TABLE_SIZE; ++i)
    {
        //if (isExpired(IdTable[i]))
        if(IdTable[i].expireTime==0)
        {
            IdTable[i].clientId = clientId;
            IdTable[i].clientAddr = clientAddr;
            IdTable[i].expireTime = ID_EXPIRE_TIME + time(NULL); // 超时时间
            break;
        }
    }
    return i;
}
/**
 * @brief 从客户端接收数据
 */
void receiveFromClient()
{
    int data_by_bytes = -1;
    unsigned char buffer[Buf_Size];
    Message message;
    memset(&message, 0, sizeof(Message));

    data_by_bytes = recvfrom(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&clientAddr, &addr_len);

    //当接收数据或解码数据出现问题时直接return
    if (data_by_bytes < 0 || decodeMessage(&message, buffer, data_by_bytes) != 0)
    {
        return;
    }
    if (LEVEL >= 1)
    {
        time_t t;
        struct tm *p;
        time(&t);
        p = localtime(&t);

        if (LEVEL == 2)
        {
            printf("\n\tReceive from Client\n");
        }
        printf("@%3d:  ", requstCount++);
        printf("%d-%02d-%02d %02d:%02d:%02d", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);
        printf("Client %15s : %-5d   ", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        printf("%s\n", message.questions->qName);

        if (LEVEL == 2)
        {
            printf("(%d bytes)\n", sizeof(buffer));
            print_query(&message);
        }
    }
    unsigned short clientId = message.id;
    int rc = searchLocal(&message);

    // rc为0表示在本地查找到信息；rc为1表示IP地址为0.0.0.0，需要被屏蔽
    if (rc == 0 || rc == 1)
    {
        unsigned char *bufferBegin = buffer;

        if (encodeMessage(&message, &bufferBegin) != 0)
        {
            return;
        }
        int buflen = bufferBegin - buffer;
        if (LEVEL == 2)
        {
            printf("\tSend to Client %s:%d ", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
            printf("(%d bytes)\n", buflen);
        }
        sendto(clientSocket, buffer, buflen, 0, (struct sockaddr *)&clientAddr, addr_len);
    }
    else
    { // 当rc为-1时，在本地的cache和ID转换表中都没有查找成功，则向外部服务器发送请求，启动中继功能
        unsigned short nId = newId(clientId, clientAddr);
        if (nId == ID_TABLE_SIZE)
        {
            if (LEVEL == 2)
                printf("ID Table is Full!\n"); // ID转换表满的报错信息
        }
        else
        {
            memcpy(buffer, &nId, sizeof(unsigned short));
            if (LEVEL == 2)
            {
                printf("\tSEND to Server %s:%d ", inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port));
                printf("(%d bytes) [ID %x=>%x]\n", data_by_bytes, clientId, nId);
            }
            data_by_bytes = sendto(serverSocket, buffer, data_by_bytes, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
        }
    }
    if (message.qdCount)
        freeQuestion(message.questions);
    if (message.anCount)
        freeResourceRecord(message.answers);
}

/**
 * @brief 从服务器接收数据，转换ID并发向客户端，最后存入cache中
 */
void receiveFromServer()
{
    int data_by_bytes = -1;
    unsigned char buffer[Buf_Size];
    Message message;
    memset(&message, 0, sizeof(Message));

    //从DNS服务器接收数据
    data_by_bytes = recvfrom(serverSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&serverAddr, &addr_len);
    if (data_by_bytes < 0 || decodeMessage(&message, buffer, data_by_bytes) != 0)
    {
        return;
    }

    if (LEVEL >= 1)
    {
        time_t t;
        struct tm *p;
        time(&t);
        p = localtime(&t);
        if (LEVEL == 2)
        {
            printf("\n\tReceive from Server\n");
        }
        printf("@%3d:  ", requstCount++);
        printf("%d-%02d-%02d %02d:%02d:%02d", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);
        printf("Server %15s : %-5d   ", inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port));
        printf("%s\n", message.questions->qName);
    }
    if (LEVEL == 2)
    {
        printf("(%d bytes)\n", sizeof(buffer));
        print_query(&message);
    }

    //进行ID转换
    unsigned short nId = message.id;
    unsigned short clientId = htons(IdTable[nId].clientId);
    memcpy(buffer, &clientId, sizeof(unsigned short));

    struct sockaddr_in ca = IdTable[nId].clientAddr;

    IdTable[nId].expireTime = 0; // 设置超时时间
    if (LEVEL == 2)
    {
        printf("\tSend to Client: %s:%d ", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        printf("(%d bytes) [ID %x=>%x]\n", data_by_bytes, nId, ntohs(clientId));
    }
    sendto(clientSocket, buffer, data_by_bytes, 0, (struct sockaddr *)&ca, sizeof(ca));

    //将资源记录类型为A的记录存入cache
    if (message.anCount)
    {
        Resource *r = message.answers;
        while (r)
        {
            if (r->type == Type_A)
            {
                char *domain_name = r->name;
                unsigned char *addr = r->rd_data.recordA.addr;
                updateCache(addr, domain_name);
                if (LEVEL == 2)
                    printCache();
            }
            r = r->next;
        }
    }

    //释放内存
    if (message.qdCount)
        freeQuestion(message.questions);
    if (message.anCount)
        freeResourceRecord(message.answers);
}

/**
 * @brief 初始化套接字
 *
 */
void initSocket()
{
    WSAStartup(MAKEWORD(2, 2), &wsaData);//添加链接库函数，指定socket版本，socket2.0后支持UDP，这里指定2.2

    //给二进制IO包使用的缓冲区
    clientSocket = socket(AF_INET, SOCK_DGRAM, 0); //采用IPV4协议，无连接套接字（UDP)
    serverSocket = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = INADDR_ANY;//监听所有端口
    clientAddr.sin_port = htons(PORT);

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(DNS_SERVER);//将点分十进制的IPv4地址转换成网络字节序列的长整型,检查DNS_SERVER是否符合ipv4地址规范
    serverAddr.sin_port = htons(PORT);

    //重新利用端口
    const int REUSE = 1;
    setsockopt(clientSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&REUSE, sizeof(REUSE));//设置套接字描述符的属性。

    if (bind(clientSocket, (SOCKADDR *)&clientAddr, addr_len) < 0)//把一个本地协议地址赋予一个套接字
    {
        printf("ERROR: can't bind: %s\n", strerror(errno));
        exit(-1);
    }
    printf("DNS server: %s\n", DNS_SERVER);
    printf("Listening on port %u\n", PORT);
}
#endif