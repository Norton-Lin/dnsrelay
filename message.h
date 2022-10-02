/**
 * @file message.h
 * @author Linzhi LiZhichao LiuXiao
 * @brief ���ķ����봦����غ���
 * @version 0.1
 * @date 2022-07-02
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef MESSAGE_H
#define MESSAGE_H
#include"head.h"
char *decodeDomainName(const unsigned char **buffer, int offset);                                    //������������ȡԭʼ�������Ǳ�����
void encodeDomainName(unsigned char **buffer, const char *domain);                                   //�������룬��xxx.xxx.x.xx����������Ϊ3xxx3xxx1x2xx0����ʽ
void decodeHeader(Message *message, const unsigned char **buffer);                                   //������ͷ
void encodeHeader(Message *message, unsigned char **buffer);                                         //��ͷ����
int decodeResourceRecord(Resource *r, const unsigned char **buffer, const unsigned char *oriBuffer); //��RFC1035��ʽ����Դ��¼���Ľ��н��룬����Ӧ����Ȩ�͸��Ӷ�
int encodeResourceRecord(Resource *r, unsigned char **buffer);                                       //����RFC1035��ʽ����Դ��¼����
int decodeMessage(Message *message, const unsigned char *buffer, int size);                          //����������Ϣ
int encodeMessage(Message *message, unsigned char **buffer);                                         //���ı���
int getARecord(unsigned char addr[4], const char domain_name[]);                                     //�����ֵ�����ѯIPV4������ַ
int searchLocal(Message *message);                                                                   //���ز�ѯ����ѯCache��Table�ֵ���
void freeResourceRecord(Resource *r);                                                                //�ͷ���Դ��¼�ڴ�
void freeQuestion(Question *q);                                                                     //�ͷ�QUESTION�ֶ��ڴ�
/**
 * @brief ������������ȡԭʼ�������Ǳ�����
 *
 * @param buffer ָ�������ĵ�ָ��ĳ���ָ��
 * @param offset ƫ����
 * @return char* ԭʼ����
 */
char *decodeDomainName(const unsigned char **buffer, int offset)
{
    char name[256];
    const unsigned char *buf = *buffer;
    int i = 0;
    int j = 0;

    if (buf[0] >= 0xc0) //��ָ�����ͣ���Ҫ����Ǩ��
    {
        int newOffset = (((int)buf[0] & 0x3f) << 8) + buf[1];         //��ȡ�µ�ַƫ����
        const unsigned char *nameAddr = *buffer - offset + newOffset; //��ȡ�µ�ַλ��
        *buffer += 2;                                                 // buffer�ƶ���λ������ָ���ƫ����
        return decodeDomainName(&nameAddr, newOffset);
    }

    while (buf[i] != 0 && buf[i] < 0xc0) // �ǵ�ַ�Σ���ʼ��ȡ
    {
        if (i != 0) //���ʵ�λ�ü���.�ָ���
        {
            name[j] = '.';
            j++;
        }
        int len = buf[i]; //����ȡ��Ϣ����
        i += 1;

        memcpy(name + j, buf + i, len); //�ֶζ�ȡ������Ϣ
        i += len;
        j += len;
    }
    if (buf[i] == 0x00) //�������ν���
    {
        i++;
    }
    else if (buf[i] >= 0xc0) //��һ��ָ��
    {
        i++;
        name[j] = '.'; //����ָ��
        j++;
        int newOffset = (((int)buf[i - 1] & 0x3f) << 8) + buf[i]; //�µ�ƫ����
        buf = *buffer - offset + newOffset;                       //������һ��ָ��ָ��ĵ�ַ
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
    return strdup(name); //����name����ĸ����ַ���
}

/**
 * @brief �������룬��xxx.xxx.x.xx����������Ϊ3xxx3xxx1x2xx0����ʽ�����ڽ���
 *
 * @param buffer ָ�������ĵ�ָ��ĳ���ָ��
 * @param domain ����������
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
        if (pos = strchr(beg, '.')) //���������Դ���'.'�ַ�����ͨ��.�ַ���λ�÷ֿ�
        {
            len = pos - beg; //��ȡ��ǰ�鳤��
            buf[i] = len;    //������д�뻺����
            i++;
            memcpy(buf + i, beg, len); //����ǰ�ֿ�����д�뻺����
            beg = pos + 1;             //�ƶ�������
        }
        else
        { //���һ��ִ�У���ʱ�Ѳ��ٴ���'.'�ַ���ֱ��ͨ�����ȼ������һ��
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
 * @brief ������ͷ
 *
 * @param message ����ָ��
 * @param buffer ָ�򻺳�����ָ���ָ��
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
 * @brief ��ͷ����
 *
 * @param message ����ָ��
 * @param buffer ָ�򻺳�����ָ���ָ��
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
 * @brief ��RFC1035��ʽ����Դ��¼���Ľ��н��룬����Ӧ����Ȩ�͸��Ӷ�
 *
 * @param r ��Դ��¼��
 * @param buffer ָ�򻺳�����ָ���ָ��
 * @param oriBuffer ƫ����
 * @return int
 */
int decodeResourceRecord(Resource *r, const unsigned char **buffer, const unsigned char *oriBuffer)
{
    r->name = decodeDomainName(buffer, *buffer - oriBuffer);

    r->type = get16bits(buffer);
    r->class = get16bits(buffer);
    r->ttl = get32bits(buffer);
    r->rdLength = get16bits(buffer);

    //���ݲ�ͬ����Դ��¼����ѡ��ͬ�Ľ������
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
 * @brief ����RFC1035��ʽ����Դ��¼����
 *
 * @param r ��Դ��¼��
 * @param buffer ָ�򻺳�����ָ���ָ��
 * @return int
 */
int encodeResourceRecord(Resource *r, unsigned char **buffer)
{
    while (r)
    {
        // ������������Ϣ����buffer������Ӧ����Դ��¼
        encodeDomainName(buffer, r->name);
        set16bits(buffer, r->type);
        set16bits(buffer, r->class);
        set32bits(buffer, r->ttl);
        set16bits(buffer, r->rdLength);

        //���ݲ�ͬ����Դ��¼�������벻ͬ��Ϣ
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
 * @brief ����������Ϣ
 *
 * @param message ָ���ĵ�ָ��
 * @param buffer ָ�򻺳�����ָ��
 * @param size ���Ĵ�С
 * @return int
 */
int decodeMessage(Message *message, const unsigned char *buffer, int size)
{
    const unsigned char *oriBuffer = buffer;

    //���뱨ͷ
    decodeHeader(message, &buffer);

    //����QUESTION�ֶ�
    for (unsigned short i = 0; i < message->qdCount; ++i)
    {
        Question *q = malloc(sizeof(Question));
        q->qName = decodeDomainName(&buffer, buffer - oriBuffer);
        q->qType = get16bits(&buffer);
        q->qClass = get16bits(&buffer);

        // ��ӵ�����ǰ��
        q->next = message->questions;
        message->questions = q;
    }
    //����ANSWER�ֶ�
    for (unsigned short i = 0; i < message->anCount; ++i)
    {
        Resource *r = malloc(sizeof(Resource));
        decodeResourceRecord(r, &buffer, oriBuffer);
        // �½�����ֶ���ӵ�����ǰ��
        r->next = message->answers;
        message->answers = r;
    }
    //����AUTHORITY�ֶ�
    for (unsigned short i = 0; i < message->nsCount; ++i)
    {
        Resource *r = malloc(sizeof(Resource));
        decodeResourceRecord(r, &buffer, oriBuffer);
        // ��ӵ�����ǰ��
        r->next = message->authorities;
        message->authorities = r;
    }

    //����ADDTIONAL�ֶ�
    for (int i = 0; i < message->arCount; ++i)
    {
        Resource *r = malloc(sizeof(Resource));
        decodeResourceRecord(r, &buffer, oriBuffer);
        // ��ӵ�����ǰ��
        r->next = message->additionals;
        message->additionals = r;
    }

    return 0;
}

/**
 * @brief ���ı���
 *
 * @param message ָ���ĵ�ָ��
 * @param buffer ָ�򻺳�����ָ���ָ��
 * @return int ��������0��ʾ���뱨��ʧ�ܣ�1��ʾ���뱨�ĳɹ�
 */
int encodeMessage(Message *message, unsigned char **buffer)
{
    Question *q;
    int flag;

    encodeHeader(message, buffer); // ���뱨ͷ
    q = message->questions;
    while (q) // ����QUESTION�ֶ�
    {
        encodeDomainName(buffer, q->qName);
        set16bits(buffer, q->qType);
        set16bits(buffer, q->qClass);

        q = q->next;
    }
    flag = 0;
    flag |= encodeResourceRecord(message->answers, buffer); // ���α���ANSWER��AUTHORITY��ADDITIONALS�ֶ�
    flag |= encodeResourceRecord(message->authorities, buffer);
    flag |= encodeResourceRecord(message->additionals, buffer);
    return flag;
}

/**
 * @brief ��ѯIPV4������ַ
 *
 * @param addr ip
 * @param domain_name ����ѯ����
 * @return int ��ѯ�����0�ɹ���1ʧ��
 */
int getARecord(unsigned char addr[4], const char domain_name[])
{
    // ������cache�в�ѯ������Ϣ
    if (findTrie(addr, domain_name, true))
    {
        if (LEVEL == 2)
            printf("\tFind '%s' in Cache.\n", domain_name);
        return 0;
    }
    // ��cache�в�ѯʧ�ܣ����ڱ����������в�ѯ������Ϣ
    if (findTrie(addr, domain_name, false))
    {
        if (LEVEL == 2)
            printf("\tFind '%s' in Table.\n", domain_name);
        return 0;
    }
    // ���ز�ѯʧ��
    if (LEVEL == 2)
        printf("\tCan't find '%s' in Cache or Table.\n", domain_name);
    return -1;
}

/**
 * @brief ���ز�ѯ����ѯCache��Table�ֵ���
 *
 * @param message ����ѯ����
 * @return int 0��ѯ�ɹ� 1��Ҫ���� -1��ѯʧ��
 */
int searchLocal(Message *message)
{
    Resource *r;
    Question *q;
    int rc;

    message->qr = 1; // QR�ֶ�Ϊ1����������Ϊ��Ӧ����
    message->aa = 1; // AA�ֶ�Ϊ1������ΪȨ��Ӧ��
    message->ra = 1; // RAΪ1������֧�ֵݹ��ѯ
    message->rcode = NoError;

    message->anCount = 0;
    message->nsCount = 0;
    message->arCount = 0;

    // ��ÿһ��QUESTION��Ҫ��������Դ��¼
    q = message->questions;
    while (q)
    {
        r = malloc(sizeof(Resource));
        memset(r, 0, sizeof(Resource));

        r->name = strdup(q->qName);
        r->type = q->qType;
        r->class = q->qClass;
        r->ttl = 60 * 60; // ��������ʱ��
        switch (q->qType)
        {
        case Type_A:
        {
            r->rdLength = 4;
            rc = getARecord(r->rd_data.recordA.addr, q->qName);
            if (rc == -1) //���ز�ѯʧ��
                break;
            int i;
            for (i = 0; i < 4; ++i)
            {
                if (r->rd_data.recordA.addr[i] != 0)
                    break;
            }

            //���ipΪ0.0.0.0����õ�ַ�����Σ������ʾ��Ϣ
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
            rc = -1; //��A���ͣ��޷��ڱ����ֵ����н��в�ѯ
            break;
        default: //�޷�ʶ�������
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
        q = q->next; // ���ж��QUESTIONʱ��ͨ������������ȷ��ÿ��QUESTION����Ӧ��
    }
    return 0;
}

/**
 * @brief �ͷ���Դ��¼�ڴ�
 * @param r Ҫ�ͷŵ���Դ��¼
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
 * @brief �ͷ�QUESTION�ֶ��ڴ�
 * @param q Ҫ�ͷŵ�QUESTION�ֶ�
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