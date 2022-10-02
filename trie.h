/**
 * @file trie.h
 * @author Linzhi
 * @brief DNS�м̷��������ֵ�����Cache�������������
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
#define maxCacheSize 100    // Cache����С
#define Name_Length 100001 //�����������
#define Buf_Size 1500       //��󻺳�����С(�����IPЭ������)
typedef struct Trie
{
    int tree[Name_Length][40];        //�ֵ���
    int parent[Name_Length];          //��¼���׽ڵ�
    bool end[Name_Length];            //�жϽڵ��Ƿ�Ϊһ�����ʵĽ���
    int totalNode;              //�ܽڵ���
    unsigned char ip[Name_Length][4]; // ipֵ
} Trie;
typedef struct Node
{
    char domainName[256];
    struct Node *next;
} LRU;
Trie *cacheTrie, *tableTrie;
LRU *head, *tail;//LRU��������ͷβָ��
int cacheSize;//��ǰcache��С
void insertNode(Trie *trie, const char *domain, unsigned char ip[4]); //���ֵ���������
void deleteNode(Trie *trie, const char *domain);                      //���ֵ���ɾ�����
int findNode(Trie *trie, const char *domain);                         //���ֵ����в�ѯһ�����
void resetDomain(char *domain);                                       //��������������дת��ΪСд
void ipTransfer(unsigned char newIp[4], char *ip);                    // IPת�������ĸ��ַ�(ASCII��Ϊ0��255)��ʾIP
void printCache();                                                    //��ǰCache�������
void updateCache(unsigned char ip[4], const char *domain);            //����LRU�㷨����Cache
bool findTrie(unsigned char ip[4], const char *domain, bool isCache); //���ֵ�����ѯ�������Ӧip���������Ƿ����Cache����
/**
 * @brief ��������������дת��ΪСд
 * @param domain ����������
 */
void resetDomain(char *domain)
{
    strlwr(domain);
}
/**
 * @brief ���ֵ���������
 * @param trie �������ֵ���
 * @param domain ����
 * @param ip IP
 */
void insertNode(Trie *trie, const char *domain, unsigned char ip[4])
{
    if (domain[0] == '\n') //����Ϊ��
        return;
    int len = 0;
    len = strlen(domain);
    char temp[500] = {0};
    strcpy(temp, domain);
    resetDomain(temp);
    int root = 0; //�ֵ��������
    int index = 0;
    for (int i = 0; i < len; i++) //�ֵ�����Ϣ����
    {
        if (temp[i] >= 'a' && temp[i] <= 'z') //����0-25��ʾ��ĸ a-z
            index = temp[i] - 'a';
        else if (temp[i] >= '0' && temp[i] <= '9') //����26-35��ʾ 0 -9
            index = temp[i] - '0' + 26;
        else if (temp[i] == '-') //����36��ʾ-
            index = 36;
        else if (temp[i] == '.') //����37��ʾ.
            index = 37;
        else
            index = 38;
        if (!trie->tree[root][index]) //���ֵΪ�գ�˵��ԭ���������ַ���������
            trie->tree[root][index] = ++trie->totalNode;
        trie->parent[trie->tree[root][index]] = root; //��¼�ֵ��������
        root = trie->tree[root][index];               //�����ӽڵ�
    }
    memcpy(trie->ip[root], ip, sizeof(unsigned char) * 4); //��¼��ǰ������IP
    trie->end[root] = true;                                //��Ǹ�λ��Ϊһ�������Ľ���
}
/**
 * @brief ���ֵ���ɾ�����
 *
 * @param trie �������ֵ���
 * @param domain ����
 */
void deleteNode(Trie *trie, const char *domain)
{
    if (domain[0] == '\n') //����Ϊ��
        return;
    int len = strlen(domain) - 1; //����������
    char temp[500] = {0};
    memcpy(temp, domain, sizeof(temp));
    bool judgeChild = false; //�ӽڵ�������ж�
    int index = 0;
    int root = findNode(trie, domain); //�ֵ��������
    if (root == 0)                     //��ѯʧ��
        return;
    resetDomain(temp);
    while (root != 0)
    {
        if (temp[len] >= 'a' && temp[len] <= 'z') //����0-25��ʾ��ĸ a-z
            index = temp[len] - 'a';
        else if (temp[len] >= '0' && temp[len] <= '9') //����26-35��ʾ 0 -9
            index = temp[len] - '0' + 26;
        else if (temp[len] == '-') //����36��ʾ-
            index = 36;
        else if (temp[len] == '.') //����37��ʾ.
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
        if (judgeChild) //���ýڵ㻹�������ӽڵ�,����ѭ��ֹͣɾ��
            break;
        trie->tree[trie->parent[root]][len] = 0;
        int tmp = trie->parent[root];
        trie->parent[root] = 0;
        root = tmp;
        len--;
    }
}
/**
 * @brief ���ֵ����в�ѯһ�����
 *
 * @param trie �������ֵ���
 * @param domain ����
 * @return int ��ѯ�����������ֵΪ0֤����ѯʧ��
 */
int findNode(Trie *trie, const char *domain)
{
    if (domain[0] == '\n') //����Ϊ��
        return 0;
    int len = strlen(domain);
    char temp[500] = {0};
    strcpy(temp, domain);
    // memcpy(temp,domain,sizeof(temp));
    resetDomain(temp);
    int root = 0; //�ֵ��������
    int index = 0;
    for (int i = 0; i < len; i++)
    {
        if (temp[i] >= 'a' && temp[i] <= 'z') //����0-25��ʾ��ĸ a-z
            index = temp[i] - 'a';
        else if (temp[i] >= '0' && temp[i] <= '9') //����26-35��ʾ 0 -9
            index = temp[i] - '0' + 26;
        else if (temp[i] == '-') //����36��ʾ-
            index = 36;
        else if (temp[i] == '.') //����37��ʾ.
            index = 37;
        else
            index = 38;
        if (!trie->tree[root][index]) //���ֵΪ�գ�˵��ԭ���������ַ�����ѯʧ��
            return 0;
        root = trie->tree[root][index]; //�����ӽڵ�
    }
    if (trie->end[root] == false) //�ý�㲢�ǽ���λ�ã���ѯʧ��
        return 0;
    return root;
}
/**
 * @brief IPת�������ĸ��ַ�(ASCII��Ϊ0��255)��ʾIP
 *
 * @param newIp ת�������IP
 * @param ip ��IP
 */
void ipTransfer(unsigned char newIp[4], char *ip)
{
    int len = strlen(ip);
    unsigned int num = 0; // ipת����
    int count = 0;        //λ��������
    for (int i = 0; i <= len; i++)
    {
        if (ip[i] == '.' || i == len)
        {
            newIp[count] = num;
            count++;
            num = 0; //���ã�������һ����
        }
        else
        {
            num = num * 10 + (ip[i] - '0');
        }
    }
}
/**
 * @brief ���cache��Ϣ
 *
 */
void printCache()
{
    printf("��ǰCache��������:\n");
    LRU *p = head->next;
    int count = 0;
    while (p != NULL)
    {
        int num = findNode(cacheTrie, p->domainName);
        printf("%d : %s :", count++, p->domainName); //���cache��ź�����
        //���ip
        printf("%u.%u.%u.%u\n", cacheTrie->ip[num][0], cacheTrie->ip[num][1], cacheTrie->ip[num][2], cacheTrie->ip[num][3]);
        p = p->next;
    }
}
/**
 * @brief ����LRU�㷨����Cache
 *
 * @param ip ip��ַ
 * @param domain ����
 */
void updateCache(unsigned char ip[4], const char *domain)
{
    int num = findNode(cacheTrie, domain);
    if (num) //��������ѯ�ɹ�
    {
        LRU *q, *p;
        q = head;
        while (q->next != NULL)
        {
            if (strcmp(q->next->domainName, domain) == 0) //�ҵ���Ӧ����
            {
                p = q->next;
                if (p->next == NULL)
                    break;
                q->next = p->next;
                p->next = NULL; //�ý���Ƶ�����ĩβ
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
        if (cacheSize < maxCacheSize) // Cache����������ֱ�Ӳ���
        {
            cacheSize++;
            q->next = NULL;
            tail->next = q;
            tail = q;
        }
        else
        {
            q->next = NULL;
            tail->next = q; //�嵽�����β
            tail = q;
            LRU *p = head->next;
            head->next = p->next;                 //ɾ��ͷ���
            deleteNode(cacheTrie, p->domainName); // Cache�ֵ���ɾ���������Ľ����Ϣ
            free(p);                              //�ͷ��ڴ�
            p=NULL;
        }
    }
}
/**
 * @brief ���ֵ�����ѯ�������Ӧip���������Ƿ����Cache����
 *
 * @param ip ip��ַ
 * @param domain ����
 * @param isChche �Ƿ���Cache
 */
bool findTrie(unsigned char ip[4], const char *domain, bool isCache)
{
    int num = 0;
    if (isCache)
        num = findNode(cacheTrie, domain);
    else
        num = findNode(tableTrie, domain);
    if (num == 0) //��ѯʧ��
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