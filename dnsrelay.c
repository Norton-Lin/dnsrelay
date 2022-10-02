/**
 @Name : dnsrelay.c
 @Author : LinZhi LiZhichao LiuXiao
 @Version : 1.0.0
 @Copyright : BUPT
 @Description : main file of DNS relay server
*/
#include "message.h"
#include "output.h"
#include"communicate.h"
void selectMode(int argc, char *argv[]);                                                             //区别操作模式，提供操作提示
void initProgram();                                                                                  //初始化字典树，读取配置文件，初始化LRU缓冲池，ID转换表
                                                                                   
/**
 * @brief 区别操作模式，提供操作提示
 * @param argc 输入参数格式
 * @param argv 参数字符串数组
 */
void selectMode(int argc, char *argv[])
{
    if (argc == 1)
    {
        printf("调试信息    级别0   无调试信息输出\n");
        printf("指定服务器为 %s: 端口:53\n", DNS_SERVER);
        printf("使用默认配置文件 %s\n", CONFIG_FILE);
        LEVEL = 2;
    }
    else if (argc == 4 && !strcmp(argv[1], "-d"))
    {
        printf("调试信息    级别1   简单调试信息输出\n");
        printf("指定服务器为 %s: 端口:53\n", argv[2]);
        printf("使用指定配置文件 %s\n", argv[3]);
        strcpy(DNS_SERVER, argv[2]);
        strcpy(CONFIG_FILE, argv[3]);
        LEVEL = 1;
    }
    else if (argc == 3 && !strcmp(argv[1], "-dd"))
    {
        printf("调试信息    级别2   冗长调试信息输出\n");
        printf("指定服务器为 %s: 端口:53\n", argv[2]);
        printf("使用默认配置文件 %s\n", CONFIG_FILE);
        strcpy(DNS_SERVER, argv[2]);
        LEVEL = 2;
    }
    else
    {
        printf("参数输入有误，请重新输入\n");
        printf("Usage:  dnsrelay [] [-d <dns-server> <dns-file>] [-dd <dns-file>] \n");
        printf("Where:          don't print debug information\n");
        printf("        -d      specify dns-server  specify dns-file  print simple debug information\n");
        printf("        -dd     specify dns-file print complex debug information\n");
        exit(-1);
    }
}

/**
 * @brief 初始化字典树，读取配置文件，初始化LRU缓冲池，ID转换表
 */
void initProgram()
{
    //初始化字典树
    cacheTrie = (Trie *)malloc(sizeof(Trie));
    tableTrie = (Trie *)malloc(sizeof(Trie));
    cacheTrie->totalNode = 0;
    tableTrie->totalNode = 0;
    cacheSize = 0;
    int count = 0;
    char domain[Buf_Size] = {0};
    char ipAddr[Buf_Size] = {0};

    //读取配置文件
    FILE *fp = NULL;
    if ((fp = fopen(CONFIG_FILE, "r")) == NULL)
    {
        printf("Error: can't open file '%s'\n", CONFIG_FILE);
        exit(-1);
    }
    unsigned char ip[4];
    while (!feof(fp))
    {
        fscanf(fp, "%s", ipAddr);
        fscanf(fp, "%s", domain);
        ipTransfer(ip, ipAddr);
        insertNode(tableTrie, domain, ip);
        if(LEVEL == 2)
            printf("%d: %s %s\n",++count,ipAddr,domain);
    }
    if(LEVEL==2)
       printf("共%d条记录",count);
    //初始化LRU
    head = (struct Node *)malloc(sizeof(struct Node));
    head->next = NULL;
    tail = head;

    //初始化ID转换表
    for (int i = 0; i < ID_TABLE_SIZE; i++)
    {
        IdTable[i].clientId = 0;
        IdTable[i].expireTime = 0;
        memset(&(IdTable[i].clientAddr), 0, sizeof(struct sockaddr_in));
    }
}



/**
 * @brief 主函数
 * @param argc 输入参数个数
 * @param argv 参数字符串数组
 */
int main(int argc, char *argv[])
{
    printInfo();
    selectMode(argc, argv);

    initProgram();
    initSocket();

    if (MODE == NONBLOCK_MODE) // nonblock
    {
        int nonBlock = 1;
        ioctlsocket(clientSocket, FIONBIO, (u_long FAR *)&nonBlock);
        ioctlsocket(serverSocket, FIONBIO, (u_long FAR *)&nonBlock);
        while (1)
        {
            receiveFromClient();
            receiveFromServer();
        }
    }
    else if (MODE == SELECT_MODE) // select
    {
        fd_set fdread; //文件句柄集合
        while (1)
        {
            FD_ZERO(&fdread);            // fdread清零
            FD_SET(clientSocket, &fdread); //将clientSock加入set
            FD_SET(serverSocket, &fdread); //将serverSock加入set
            TIMEVAL tv;                  //设置超时等待时间
            tv.tv_sec = 0;               // 0s
            tv.tv_usec = 1;              // 1us
            int ret = select(0, &fdread, NULL, NULL, &tv);
            if (SOCKET_ERROR == ret) // select返回-1，发生错误
            {
                printf("ERROR SELECT:%d.\n", WSAGetLastError());
            }
            if (ret > 0)
            {
                if (FD_ISSET(clientSocket, &fdread))
                {
                    receiveFromClient();
                }
                if (FD_ISSET(serverSocket, &fdread))
                {
                    receiveFromServer();
                }
            }
        }
    }

    closesocket(clientSocket);//此函数关闭套接字s，并释放分配给该套接字的资源
    closesocket(serverSocket);
    WSACleanup();//解除与Socket库的绑定并且释放Socket库所占用的系统资源。
    return 0;
}