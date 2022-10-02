/**
 * @file trie.h
 * @author Linzhi
 * @brief DNS中继服务器的字典树、Cache定义与基本操作
 * @version 0.1
 * @date 2022-07-02
 * @copyright BUPT (c) 2022
 * 
 */
#ifndef TRIE_H
#define TRIE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#define maxCacheSize 100    // Cache最大大小
#define Name_Length 100001 //最大域名长度
#define Buf_Size 1500       //最大缓冲区大小(网络层IP协议限制)
typedef struct Trie
{
    int tree[Name_Length][40];        //字典树
    int parent[Name_Length];          //记录父亲节点
    bool end[Name_Length];            //判断节点是否为一个单词的结束
    int totalNode;              //总节点数
    unsigned char ip[Name_Length][4]; // ip值
} Trie;
typedef struct Node
{
    char domainName[256];
    struct Node *next;
} LRU;
Trie *cacheTrie, *tableTrie;
LRU *head, *tail;//LRU辅助链表头尾指针
int cacheSize;//当前cache大小
void insertNode(Trie *trie, const char *domain, unsigned char ip[4]); //向字典树插入结点
void deleteNode(Trie *trie, const char *domain);                      //向字典树删除结点
int findNode(Trie *trie, const char *domain);                         //从字典树中查询一个结点
void resetDomain(char *domain);                                       //重置域名，将大写转换为小写
void ipTransfer(unsigned char newIp[4], char *ip);                    // IP转换，用四个字符(ASCII码为0—255)表示IP
void printCache();                                                    //当前Cache内容输出
void updateCache(unsigned char ip[4], const char *domain);            //根据LRU算法更新Cache
bool findTrie(unsigned char ip[4], const char *domain, bool isCache); //在字典树查询域名与对应ip，并决定是否进行Cache更新
/**
 * @brief 重置域名，将大写转换为小写
 * @param domain 待重置域名
 */
void resetDomain(char *domain)
{
    strlwr(domain);
}
/**
 * @brief 向字典树插入结点
 * @param trie 待操作字典树
 * @param domain 域名
 * @param ip IP
 */
void insertNode(Trie *trie, const char *domain, unsigned char ip[4])
{
    if (domain[0] == '\n') //域名为空
        return;
    int len = 0;
    len = strlen(domain);
    char temp[500] = {0};
    strcpy(temp, domain);
    resetDomain(temp);
    int root = 0; //字典树根结点
    int index = 0;
    for (int i = 0; i < len; i++) //字典树信息插入
    {
        if (temp[i] >= 'a' && temp[i] <= 'z') //数组0-25表示字母 a-z
            index = temp[i] - 'a';
        else if (temp[i] >= '0' && temp[i] <= '9') //数组26-35表示 0 -9
            index = temp[i] - '0' + 26;
        else if (temp[i] == '-') //数组36表示-
            index = 36;
        else if (temp[i] == '.') //数组37表示.
            index = 37;
        else
            index = 38;
        if (!trie->tree[root][index]) //结点值为空，说明原本不存在字符，赋予编号
            trie->tree[root][index] = ++trie->totalNode;
        trie->parent[trie->tree[root][index]] = root; //记录字典树父结点
        root = trie->tree[root][index];               //进入子节点
    }
    memcpy(trie->ip[root], ip, sizeof(unsigned char) * 4); //记录当前域名的IP
    trie->end[root] = true;                                //标记该位置为一个域名的结束
}
/**
 * @brief 向字典树删除结点
 *
 * @param trie 待操作字典树
 * @param domain 域名
 */
void deleteNode(Trie *trie, const char *domain)
{
    if (domain[0] == '\n') //域名为空
        return;
    int len = strlen(domain) - 1; //该域名长度
    char temp[500] = {0};
    memcpy(temp, domain, sizeof(temp));
    bool judgeChild = false; //子节点存在性判断
    int index = 0;
    int root = findNode(trie, domain); //字典树根结点
    if (root == 0)                     //查询失败
        return;
    resetDomain(temp);
    while (root != 0)
    {
        if (temp[len] >= 'a' && temp[len] <= 'z') //数组0-25表示字母 a-z
            index = temp[len] - 'a';
        else if (temp[len] >= '0' && temp[len] <= '9') //数组26-35表示 0 -9
            index = temp[len] - '0' + 26;
        else if (temp[len] == '-') //数组36表示-
            index = 36;
        else if (temp[len] == '.') //数组37表示.
            index = 37;
        else
            index = 38;
        for (int i = 0; i < 40; i++)
        {
            if (trie->tree[root][i] != 0)
            {
                judgeChild = true;
                break;
            }
        }
        if (judgeChild) //若该节点还有其他子节点,跳出循环停止删除
            break;
        trie->tree[trie->parent[root]][len] = 0;
        int tmp = trie->parent[root];
        trie->parent[root] = 0;
        root = tmp;
        len--;
    }
}
/**
 * @brief 从字典数中查询一个结点
 *
 * @param trie 待操作字典树
 * @param domain 域名
 * @return int 查询结果，当返回值为0证明查询失败
 */
int findNode(Trie *trie, const char *domain)
{
    if (domain[0] == '\n') //域名为空
        return 0;
    int len = strlen(domain);
    char temp[500] = {0};
    strcpy(temp, domain);
    // memcpy(temp,domain,sizeof(temp));
    resetDomain(temp);
    int root = 0; //字典树根结点
    int index = 0;
    for (int i = 0; i < len; i++)
    {
        if (temp[i] >= 'a' && temp[i] <= 'z') //数组0-25表示字母 a-z
            index = temp[i] - 'a';
        else if (temp[i] >= '0' && temp[i] <= '9') //数组26-35表示 0 -9
            index = temp[i] - '0' + 26;
        else if (temp[i] == '-') //数组36表示-
            index = 36;
        else if (temp[i] == '.') //数组37表示.
            index = 37;
        else
            index = 38;
        if (!trie->tree[root][index]) //结点值为空，说明原本不存在字符，查询失败
            return 0;
        root = trie->tree[root][index]; //进入子节点
    }
    if (trie->end[root] == false) //该结点并非结束位置，查询失败
        return 0;
    return root;
}
/**
 * @brief IP转换，用四个字符(ASCII码为0—255)表示IP
 *
 * @param newIp 转换后的新IP
 * @param ip 旧IP
 */
void ipTransfer(unsigned char newIp[4], char *ip)
{
    int len = strlen(ip);
    unsigned int num = 0; // ip转换数
    int count = 0;        //位计数变量
    for (int i = 0; i <= len; i++)
    {
        if (ip[i] == '.' || i == len)
        {
            newIp[count] = num;
            count++;
            num = 0; //重置，计算下一个数
        }
        else
        {
            num = num * 10 + (ip[i] - '0');
        }
    }
}
/**
 * @brief 输出cache信息
 *
 */
void printCache()
{
    printf("当前Cache内容如下:\n");
    LRU *p = head->next;
    int count = 0;
    while (p != NULL)
    {
        int num = findNode(cacheTrie, p->domainName);
        printf("%d : %s :", count++, p->domainName); //输出cache编号和域名
        //输出ip
        printf("%u.%u.%u.%u\n", cacheTrie->ip[num][0], cacheTrie->ip[num][1], cacheTrie->ip[num][2], cacheTrie->ip[num][3]);
        p = p->next;
    }
}
/**
 * @brief 根据LRU算法更新Cache
 *
 * @param ip ip地址
 * @param domain 域名
 */
void updateCache(unsigned char ip[4], const char *domain)
{
    int num = findNode(cacheTrie, domain);
    if (num) //该域名查询成功
    {
        LRU *q, *p;
        q = head;
        while (q->next != NULL)
        {
            if (strcmp(q->next->domainName, domain) == 0) //找到对应域名
            {
                p = q->next;
                if (p->next == NULL)
                    break;
                q->next = p->next;
                p->next = NULL; //该结点移到链表末尾
                tail->next = p;
                tail = p;
                break;
            }
            q = q->next;
        }
    }
    else
    {
        LRU *q = (LRU *)malloc(sizeof(LRU));
        strcpy(q->domainName, domain);
        insertNode(cacheTrie, domain, ip);
        if (cacheSize < maxCacheSize) // Cache还有容量，直接插入
        {
            cacheSize++;
            q->next = NULL;
            tail->next = q;
            tail = q;
        }
        else
        {
            q->next = NULL;
            tail->next = q; //插到链表结尾
            tail = q;
            LRU *p = head->next;
            head->next = p->next;                 //删除头结点
            deleteNode(cacheTrie, p->domainName); // Cache字典树删除被丢弃的结点信息
            free(p);                              //释放内存
            p=NULL;
        }
    }
}
/**
 * @brief 在字典树查询域名与对应ip，并决定是否进行Cache更新
 *
 * @param ip ip地址
 * @param domain 域名
 * @param isChche 是否是Cache
 */
bool findTrie(unsigned char ip[4], const char *domain, bool isCache)
{
    int num = 0;
    if (isCache)
        num = findNode(cacheTrie, domain);
    else
        num = findNode(tableTrie, domain);
    if (num == 0) //查询失败
        return false;
    if (isCache)
        memcpy(ip, cacheTrie->ip[num], sizeof(unsigned char) * 4);
    else
        memcpy(ip, tableTrie->ip[num], sizeof(unsigned char) * 4);
    if (isCache)
        updateCache(ip, domain);
    return true;
}
#endif // TRIE_H