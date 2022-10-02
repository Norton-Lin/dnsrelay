/**
 * @file util.h
 * @author Linzhi
 * @brief 基本位信息获取与设置
 * @version 0.1
 * @date 2022-07-02
 * @copyright BUPT (c) 2022
 * 
 */
#ifndef UTIL_H
#define UTIL_H
size_t get8bits(const unsigned char **buffer);                                                       //从缓冲区获取8bits信息
size_t get16bits(const unsigned char **buffer);                                                      //从缓冲区获取16bits信息
size_t get32bits(const unsigned char **buffer);                                                      //向缓冲区获取32bits信息
void set8bits(unsigned char **buffer, unsigned char value);                                          //向缓冲区填充8bits信息
void set16bits(unsigned char **buffer, unsigned short value);                                        //向缓冲区填充16bits信息
void set32bits(unsigned char **buffer, unsigned int value);                                          //向缓冲区填充32bits信息
/**
 * @brief 从缓冲区获取8bits信息
 *
 * @param buffer 指向缓冲区指针的指针
 * @return size_t 返回8bits信息
 */
size_t get8bits(const unsigned char **buffer)
{
    unsigned char value;
    memcpy(&value, *buffer, 1);
    *buffer += 1;
    return value;
}

/**
 * @brief 从缓冲区获取16bits信息
 *
 * @param buffer 指向缓冲区指针的指针
 * @return size_t 返回16bits信息
 */
size_t get16bits(const unsigned char **buffer)
{
    unsigned short value;

    memcpy(&value, *buffer, 2);
    *buffer += 2;

    return ntohs(value);
}

/**
 * @brief 从缓冲区获取32bits信息
 *
 * @param buffer 指向缓冲区指针的指针
 * @return size_t 返回32bits信息
 */
size_t get32bits(const unsigned char **buffer)
{
    unsigned int value;

    memcpy(&value, *buffer, 4);
    *buffer += 4;

    return ntohl(value);
}

/**
 * @brief 向缓冲区填充8bits信息
 *
 * @param buffer 指向缓冲区指针的指针
 * @param value 待填充信息
 */
void set8bits(unsigned char **buffer, unsigned char value)
{
    memcpy(*buffer, &value, 1);
    *buffer += 1;
}

/**
 * @brief 向缓冲区填充16bits信息
 *
 * @param buffer 指向缓冲区指针的指针
 * @param value 待填充信息
 */
void set16bits(unsigned char **buffer, unsigned short value)
{
    value = htons(value);
    memcpy(*buffer, &value, 2);
    *buffer += 2;
}

/**
 * @brief 向缓冲区填充32bits信息
 *
 * @param buffer 指向缓冲区指针的指针
 * @param value 待填充信息
 */
void set32bits(unsigned char **buffer, unsigned int value)
{
    value = htonl(value);
    memcpy(*buffer, &value, 4);
    *buffer += 4;
}
#endif 