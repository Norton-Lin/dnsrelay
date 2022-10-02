/**
 * @file message.h
 * @author Linzhi LiZhichao LiuXiao
 * @brief 报文分析与处理相关函数
 * @version 0.1
 * @date 2022-07-02
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef MESSAGE_H
#define MESSAGE_H
#include"head.h"
char *decodeDomainName(const unsigned char **buffer, int offset);                                    //解析域名，获取原始域名（非别名）
void encodeDomainName(unsigned char **buffer, const char *domain);                                   //域名编码，将xxx.xxx.x.xx的域名重置为3xxx3xxx1x2xx0的形式
void decodeHeader(Message *message, const unsigned char **buffer);                                   //解析报头
void encodeHeader(Message *message, unsigned char **buffer);                                         //报头编码
int decodeResourceRecord(Resource *r, const unsigned char **buffer, const unsigned char *oriBuffer); //对RFC1035格式的资源记录报文进行解码，包括应答、授权和附加段
int encodeResourceRecord(Resource *r, unsigned char **buffer);                                       //编码RFC1035格式的资源记录报文
int decodeMessage(Message *message, const unsigned char *buffer, int size);                          //解析报文信息
int encodeMessage(Message *message, unsigned char **buffer);                                         //报文编码
int getARecord(unsigned char addr[4], const char domain_name[]);                                     //本地字典树查询IPV4域名地址
int searchLocal(Message *message);                                                                   //本地查询，查询Cache和Table字典树
void freeResourceRecord(Resource *r);                                                                //释放资源记录内存
void freeQuestion(Question *q);                                                                     //释放QUESTION字段内存
/**
 * @brief 解析域名，获取原始域名（非别名）
 *
 * @param buffer 指向域名的的指针的常量指针
 * @param offset 偏移量
 * @return char* 原始域名
 */
char *decodeDomainName(const unsigned char **buffer, int offset)
{
    char name[256];
    const unsigned char *buf = *buffer;
    int i = 0;
    int j = 0;

    if (buf[0] >= 0xc0) //是指针类型，需要进行迁移
    {
        int newOffset = (((int)buf[0] & 0x3f) << 8) + buf[1];         //获取新地址偏移量
        const unsigned char *nameAddr = *buffer - offset + newOffset; //获取新地址位置
        *buffer += 2;                                                 // buffer移动两位，跳过指针和偏移量
        return decodeDomainName(&nameAddr, newOffset);
    }

    while (buf[i] != 0 && buf[i] < 0xc0) // 是地址段，开始读取
    {
        if (i != 0) //在适当位置加入.分隔符
        {
            name[j] = '.';
            j++;
        }
        int len = buf[i]; //待读取信息长度
        i += 1;

        memcpy(name + j, buf + i, len); //分段读取域名信息
        i += len;
        j += len;
    }
    if (buf[i] == 0x00) //该域名段结束
    {
        i++;
    }
    else if (buf[i] >= 0xc0) //下一个指针
    {
        i++;
        name[j] = '.'; //加入分割符
        j++;
        int newOffset = (((int)buf[i - 1] & 0x3f) << 8) + buf[i]; //新的偏移量
        buf = *buffer - offset + newOffset;                       //进入下一个指针指向的地址
        char *nameRemain = decodeDomainName(&buf, newOffset);
        memcpy(name + j, nameRemain, strlen(nameRemain));
        j += strlen(nameRemain);
        i++;
    }
    else
    {
        printf("Error: decode_domain_name\n");
    }

    *buffer += i;
    name[j] = '\0';
    return strdup(name); //返回name数组的复制字符串
}

/**
 * @brief 域名编码，将xxx.xxx.x.xx的域名重置为3xxx3xxx1x2xx0的形式，便于解析
 *
 * @param buffer 指向域名的的指针的常量指针
 * @param domain 待编码域名
 */
void encodeDomainName(unsigned char **buffer, const char *domain)
{
    unsigned char *buf = *buffer;
    const char *beg = domain;
    const char *pos;
    int len = 0;
    int i = 0;
    int total;
    for (total = strlen(domain); total > 0; total -= len)
    {
        if (pos = strchr(beg, '.')) //若域名中仍存在'.'字符，则通过.字符的位置分块
        {
            len = pos - beg; //获取当前块长度
            buf[i] = len;    //将长度写入缓冲区
            i++;
            memcpy(buf + i, beg, len); //将当前分块内容写入缓冲区
            beg = pos + 1;             //移动计数器
        }
        else
        { //最后一趟执行，此时已不再存在'.'字符，直接通过长度检索最后一块
            len = strlen(domain) - (beg - domain);
            buf[i] = len;
            i++;
            memcpy(buf + i, beg, len);
        }
        i += len;
    }
    buf[i++] = 0;
    *buffer += i;
}

/**
 * @brief 解析报头
 *
 * @param message 报文指针
 * @param buffer 指向缓冲区的指针的指针
 */
void decodeHeader(Message *message, const unsigned char **buffer)
{
    message->id = get16bits(buffer);
    uint32_t flags = get16bits(buffer);
    message->qr = (flags & QR_MASK) >> 15;
    message->opcode = (flags & OPCODE_MASK) >> 11;
    message->aa = (flags & AA_MASK) >> 10;
    message->tc = (flags & TC_MASK) >> 9;
    message->rd = (flags & RD_MASK) >> 8;
    message->ra = (flags & RA_MASK) >> 7;
    message->rcode = (flags & RCODE_MASK) >> 0;
    message->qdCount = get16bits(buffer);
    message->anCount = get16bits(buffer);
    message->nsCount = get16bits(buffer);
    message->arCount = get16bits(buffer);
}

/**
 * @brief 报头编码
 *
 * @param message 报文指针
 * @param buffer 指向缓冲区的指针的指针
 */
void encodeHeader(Message *message, unsigned char **buffer)
{
    set16bits(buffer, message->id);

    int flags = 0;
    flags |= (message->qr << 15) & QR_MASK;
    flags |= (message->opcode << 11) & OPCODE_MASK;
    flags |= (message->aa << 10) & AA_MASK;
    flags |= (message->tc << 9) & TC_MASK;
    flags |= (message->rd << 8) & RD_MASK;
    flags |= (message->ra << 7) & RA_MASK;
    flags |= (message->rcode << 0) & RCODE_MASK;
    set16bits(buffer, flags);
    set16bits(buffer, message->qdCount);
    set16bits(buffer, message->anCount);
    set16bits(buffer, message->nsCount);
    set16bits(buffer, message->arCount);
}

/**
 * @brief 对RFC1035格式的资源记录报文进行解码，包括应答、授权和附加段
 *
 * @param r 资源记录段
 * @param buffer 指向缓冲区的指针的指针
 * @param oriBuffer 偏移量
 * @return int
 */
int decodeResourceRecord(Resource *r, const unsigned char **buffer, const unsigned char *oriBuffer)
{
    r->name = decodeDomainName(buffer, *buffer - oriBuffer);

    r->type = get16bits(buffer);
    r->class = get16bits(buffer);
    r->ttl = get32bits(buffer);
    r->rdLength = get16bits(buffer);

    //根据不同的资源记录类型选择不同的解码过程
    switch (r->type)
    {
    case Type_A:
    {
        for (int i = 0; i < 4; ++i)
            r->rd_data.recordA.addr[i] = get8bits(buffer);
    }
    break;
    case Type_NS:
        r->rd_data.recordNS.name = decodeDomainName(buffer, *buffer - oriBuffer);
        break;
    case Type_CNAME:
        r->rd_data.recordCNAME.name = decodeDomainName(buffer, *buffer - oriBuffer);
        break;
    case Type_SOA:
    {
        r->rd_data.recordSOA.MName = decodeDomainName(buffer, *buffer - oriBuffer);
        r->rd_data.recordSOA.RName = decodeDomainName(buffer, *buffer - oriBuffer);
        r->rd_data.recordSOA.serial = get32bits(buffer);
        r->rd_data.recordSOA.refresh = get32bits(buffer);
        r->rd_data.recordSOA.retry = get32bits(buffer);
        r->rd_data.recordSOA.expire = get32bits(buffer);
        r->rd_data.recordSOA.minimum = get32bits(buffer);
    }
    break;
    case Type_PTR:
        r->rd_data.recordPTR.name = decodeDomainName(buffer, *buffer - oriBuffer);
        break;
    case Type_MX:
    {
        r->rd_data.recordMX.preference = get16bits(buffer);
        r->rd_data.recordMX.exchange = decodeDomainName(buffer, *buffer - oriBuffer);
    }
    break;
    case Type_TXT:
    {
        r->rd_data.recordTXT.dataLength = get8bits(buffer);
        unsigned char txt_len = r->rd_data.recordTXT.dataLength;
        char *txtData = malloc(txt_len + 1);
        for (int i = 0; i < txt_len; ++i)
        {
            printf("%d ", i);
            txtData[i] = get8bits(buffer);
        }
        txtData[txt_len] = '\0';
        r->rd_data.recordTXT.data = strdup(txtData);
    }
    break;
    case Type_AAAA:
    {
        for (int i = 0; i < 16; ++i)
            r->rd_data.recordAAAA.addr[i] = get8bits(buffer);
    }
    break;
    default:
        fprintf(stderr, "Error @decodeResourceRecord: Unknown type %u. => Ignore resource record.\n", r->type);
        return -1;
    }
    return 0;
}

/**
 * @brief 编码RFC1035格式的资源记录报文
 *
 * @param r 资源记录段
 * @param buffer 指向缓冲区的指针的指针
 * @return int
 */
int encodeResourceRecord(Resource *r, unsigned char **buffer)
{
    while (r)
    {
        // 编码域名后将信息置入buffer，构成应答资源记录
        encodeDomainName(buffer, r->name);
        set16bits(buffer, r->type);
        set16bits(buffer, r->class);
        set32bits(buffer, r->ttl);
        set16bits(buffer, r->rdLength);

        //根据不同的资源记录类型置入不同信息
        switch (r->type)
        {
        case Type_A:
            for (int i = 0; i < 4; ++i)
                set8bits(buffer, r->rd_data.recordA.addr[i]);
            break;
        case Type_TXT:
            set8bits(buffer, r->rd_data.recordTXT.dataLength);
            for (int i = 0; i < r->rd_data.recordTXT.dataLength; i++)
                set8bits(buffer, r->rd_data.recordTXT.data[i]);
            break;
        case Type_AAAA:
            for (int i = 0; i < 16; ++i)
                set8bits(buffer, r->rd_data.recordAAAA.addr[i]);
            break;
        default:
            fprintf(stderr, "ERROR @encode_resource_records: Unknown type %u. => Ignore resource record.\n", r->type);
            return 1;
        }

        r = r->next;
    }
    return 0;
}

/**
 * @brief 解析报文信息
 *
 * @param message 指向报文的指针
 * @param buffer 指向缓冲区的指针
 * @param size 报文大小
 * @return int
 */
int decodeMessage(Message *message, const unsigned char *buffer, int size)
{
    const unsigned char *oriBuffer = buffer;

    //解码报头
    decodeHeader(message, &buffer);

    //解码QUESTION字段
    for (unsigned short i = 0; i < message->qdCount; ++i)
    {
        Question *q = malloc(sizeof(Question));
        q->qName = decodeDomainName(&buffer, buffer - oriBuffer);
        q->qType = get16bits(&buffer);
        q->qClass = get16bits(&buffer);

        // 添加到链表前端
        q->next = message->questions;
        message->questions = q;
    }
    //解码ANSWER字段
    for (unsigned short i = 0; i < message->anCount; ++i)
    {
        Resource *r = malloc(sizeof(Resource));
        decodeResourceRecord(r, &buffer, oriBuffer);
        // 新解码的字段添加到链表前端
        r->next = message->answers;
        message->answers = r;
    }
    //解码AUTHORITY字段
    for (unsigned short i = 0; i < message->nsCount; ++i)
    {
        Resource *r = malloc(sizeof(Resource));
        decodeResourceRecord(r, &buffer, oriBuffer);
        // 添加到链表前端
        r->next = message->authorities;
        message->authorities = r;
    }

    //解码ADDTIONAL字段
    for (int i = 0; i < message->arCount; ++i)
    {
        Resource *r = malloc(sizeof(Resource));
        decodeResourceRecord(r, &buffer, oriBuffer);
        // 添加到链表前端
        r->next = message->additionals;
        message->additionals = r;
    }

    return 0;
}

/**
 * @brief 报文编码
 *
 * @param message 指向报文的指针
 * @param buffer 指向缓冲区的指针的指针
 * @return int 编码结果，0表示编码报文失败，1表示编码报文成功
 */
int encodeMessage(Message *message, unsigned char **buffer)
{
    Question *q;
    int flag;

    encodeHeader(message, buffer); // 编码报头
    q = message->questions;
    while (q) // 编码QUESTION字段
    {
        encodeDomainName(buffer, q->qName);
        set16bits(buffer, q->qType);
        set16bits(buffer, q->qClass);

        q = q->next;
    }
    flag = 0;
    flag |= encodeResourceRecord(message->answers, buffer); // 依次编码ANSWER、AUTHORITY、ADDITIONALS字段
    flag |= encodeResourceRecord(message->authorities, buffer);
    flag |= encodeResourceRecord(message->additionals, buffer);
    return flag;
}

/**
 * @brief 查询IPV4域名地址
 *
 * @param addr ip
 * @param domain_name 待查询域名
 * @return int 查询结果，0成功，1失败
 */
int getARecord(unsigned char addr[4], const char domain_name[])
{
    // 首先在cache中查询域名信息
    if (findTrie(addr, domain_name, true))
    {
        if (LEVEL == 2)
            printf("\tFind '%s' in Cache.\n", domain_name);
        return 0;
    }
    // 在cache中查询失败，则在本地域名表中查询域名信息
    if (findTrie(addr, domain_name, false))
    {
        if (LEVEL == 2)
            printf("\tFind '%s' in Table.\n", domain_name);
        return 0;
    }
    // 本地查询失败
    if (LEVEL == 2)
        printf("\tCan't find '%s' in Cache or Table.\n", domain_name);
    return -1;
}

/**
 * @brief 本地查询，查询Cache和Table字典树
 *
 * @param message 待查询报文
 * @return int 0查询成功 1需要屏蔽 -1查询失败
 */
int searchLocal(Message *message)
{
    Resource *r;
    Question *q;
    int rc;

    message->qr = 1; // QR字段为1，代表本报文为响应报文
    message->aa = 1; // AA字段为1，代表为权威应答
    message->ra = 1; // RA为1，代表支持递归查询
    message->rcode = NoError;

    message->anCount = 0;
    message->nsCount = 0;
    message->arCount = 0;

    // 对每一个QUESTION都要附加其资源记录
    q = message->questions;
    while (q)
    {
        r = malloc(sizeof(Resource));
        memset(r, 0, sizeof(Resource));

        r->name = strdup(q->qName);
        r->type = q->qType;
        r->class = q->qClass;
        r->ttl = 60 * 60; // 设置生存时间
        switch (q->qType)
        {
        case Type_A:
        {
            r->rdLength = 4;
            rc = getARecord(r->rd_data.recordA.addr, q->qName);
            if (rc == -1) //本地查询失败
                break;
            int i;
            for (i = 0; i < 4; ++i)
            {
                if (r->rd_data.recordA.addr[i] != 0)
                    break;
            }

            //如果ip为0.0.0.0代表该地址被屏蔽，输出提示信息
            if (i == 4)
            {
                if (LEVEL >= 1)
                    printf("Shield: %s\n", q->qName);
                message->rcode = NXDomain;
                rc = 1;
                return rc;
            }
        }
        break;
        case Type_NS:
        case Type_CNAME:
        case Type_SOA:
        case Type_PTR:
        case Type_MX:
        case Type_TXT:
        case Type_AAAA:
            rc = -1; //非A类型，无法在本地字典树中进行查询
            break;
        default: //无法识别的类型
            rc = -1;
            message->rcode = NOtImp;
            printf("Cannot answer question of type %d.\n", q->qType);
        }
        if (rc == 0)
        {
            message->anCount++;
            r->next = message->answers;
            message->answers = r;
        }
        else
        {
            free(r->name);
            free(r);
            return -1;
        }
        q = q->next; // 当有多个QUESTION时，通过遍历链表来确保每个QUESTION都被应答
    }
    return 0;
}

/**
 * @brief 释放资源记录内存
 * @param r 要释放的资源记录
 */
void freeResourceRecord(Resource *r)
{
    Resource *next;
    while (r)
    {
        free(r->name);
        next = r->next;
        free(r);
        r = next;
    }
}

/**
 * @brief 释放QUESTION字段内存
 * @param q 要释放的QUESTION字段
 */
void freeQuestion(Question *q)
{
    Question *next;

    while (q)
    {
        free(q->qName);
        next = q->next;
        free(q);
        q = next;
    }
}

#endif