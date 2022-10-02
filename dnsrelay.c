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
void selectMode(int argc, char *argv[]);                                                             //�������ģʽ���ṩ������ʾ
void initProgram();                                                                                  //��ʼ���ֵ�������ȡ�����ļ�����ʼ��LRU����أ�IDת����
                                                                                   
/**
 * @brief �������ģʽ���ṩ������ʾ
 * @param argc ���������ʽ
 * @param argv �����ַ�������
 */
void selectMode(int argc, char *argv[])
{
    if (argc == 1)
    {
        printf("������Ϣ    ����0   �޵�����Ϣ���\n");
        printf("ָ��������Ϊ %s: �˿�:53\n", DNS_SERVER);
        printf("ʹ��Ĭ�������ļ� %s\n", CONFIG_FILE);
        LEVEL = 2;
    }
    else if (argc == 4 && !strcmp(argv[1], "-d"))
    {
        printf("������Ϣ    ����1   �򵥵�����Ϣ���\n");
        printf("ָ��������Ϊ %s: �˿�:53\n", argv[2]);
        printf("ʹ��ָ�������ļ� %s\n", argv[3]);
        strcpy(DNS_SERVER, argv[2]);
        strcpy(CONFIG_FILE, argv[3]);
        LEVEL = 1;
    }
    else if (argc == 3 && !strcmp(argv[1], "-dd"))
    {
        printf("������Ϣ    ����2   �߳�������Ϣ���\n");
        printf("ָ��������Ϊ %s: �˿�:53\n", argv[2]);
        printf("ʹ��Ĭ�������ļ� %s\n", CONFIG_FILE);
        strcpy(DNS_SERVER, argv[2]);
        LEVEL = 2;
    }
    else
    {
        printf("����������������������\n");
        printf("Usage:  dnsrelay [] [-d <dns-server> <dns-file>] [-dd <dns-file>] \n");
        printf("Where:          don't print debug information\n");
        printf("        -d      specify dns-server  specify dns-file  print simple debug information\n");
        printf("        -dd     specify dns-file print complex debug information\n");
        exit(-1);
    }
}

/**
 * @brief ��ʼ���ֵ�������ȡ�����ļ�����ʼ��LRU����أ�IDת����
 */
void initProgram()
{
    //��ʼ���ֵ���
    cacheTrie = (Trie *)malloc(sizeof(Trie));
    tableTrie = (Trie *)malloc(sizeof(Trie));
    cacheTrie->totalNode = 0;
    tableTrie->totalNode = 0;
    cacheSize = 0;
    int count = 0;
    char domain[Buf_Size] = {0};
    char ipAddr[Buf_Size] = {0};

    //��ȡ�����ļ�
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
       printf("��%d����¼",count);
    //��ʼ��LRU
    head = (struct Node *)malloc(sizeof(struct Node));
    head->next = NULL;
    tail = head;

    //��ʼ��IDת����
    for (int i = 0; i < ID_TABLE_SIZE; i++)
    {
        IdTable[i].clientId = 0;
        IdTable[i].expireTime = 0;
        memset(&(IdTable[i].clientAddr), 0, sizeof(struct sockaddr_in));
    }
}



/**
 * @brief ������
 * @param argc �����������
 * @param argv �����ַ�������
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
        fd_set fdread; //�ļ��������
        while (1)
        {
            FD_ZERO(&fdread);            // fdread����
            FD_SET(clientSocket, &fdread); //��clientSock����set
            FD_SET(serverSocket, &fdread); //��serverSock����set
            TIMEVAL tv;                  //���ó�ʱ�ȴ�ʱ��
            tv.tv_sec = 0;               // 0s
            tv.tv_usec = 1;              // 1us
            int ret = select(0, &fdread, NULL, NULL, &tv);
            if (SOCKET_ERROR == ret) // select����-1����������
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

    closesocket(clientSocket);//�˺����ر��׽���s�����ͷŷ�������׽��ֵ���Դ
    closesocket(serverSocket);
    WSACleanup();//�����Socket��İ󶨲����ͷ�Socket����ռ�õ�ϵͳ��Դ��
    return 0;
}