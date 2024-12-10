/****************************************Copyright (c)**************************************************
**                               Guangzhou ZHIYUAN electronics Co.,LTD.
**                                     
**                                 http://www.zyinside.com
**
**--------------File Info-------------------------------------------------------------------------------
** File name:			sha1.c
** Last modified Date:  2007-04-07
** Last Version:		1.0
** Descriptions:		SHA-1算法, 算法来源于RFC3174
**------------------------------------------------------------------------------------------------------
** Created by:			NA
** Created date:		1995
** Version:				NA
** Descriptions:		NA
**------------------------------------------------------------------------------------------------------
** Modified by:         chenmingji
** Modified date:       2007-04-18
** Version:             1.0
** Descriptions:        The original version
********************************************************************************************************/

//#include "stdafx.h"
#include "config.h"
#include "sha1.h"

/* Define the SHA1 circular left shift macro */
#define SHA1CircularShift(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))

/* Local Function Prototyptes */
static void SHA1PadMessage(SHA1Context *);
static void SHA1ProcessMessageBlock(SHA1Context *);

/*********************************************************************************************************
** Function name:			SHA1Init
** Descriptions:			初始化SHA-1算法寄存器
** input parameters:		context    : SHA-1算法寄存器
**                          input      : 输入分组
**                          inputLen   : 输入的分组的长度
** Returned value:			shaSuccess : 成功
**                          shaNull    : context为空
** Created by:				NA
** Created Date:			1995
**-------------------------------------------------------------------------------------------------------
** Modified by:				Chenmingji
** Modified date:			2007-04-18
**------------------------------------------------------------------------------------------------------
********************************************************************************************************/
        int SHA1Init(SHA1Context *context)
{
    if (!context)
    {
        return shaNull;
    }

    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Message_Block_Index    = 0;

    context->Intermediate_Hash[0]   = 0x67452301;
    context->Intermediate_Hash[1]   = 0xEFCDAB89;
    context->Intermediate_Hash[2]   = 0x98BADCFE;
    context->Intermediate_Hash[3]   = 0x10325476;
    context->Intermediate_Hash[4]   = 0xC3D2E1F0;

    context->Computed   = 0;
    context->Corrupted  = 0;

    return shaSuccess;
}

/*********************************************************************************************************
** Function name:			SHA1Final
** Descriptions:			SHA-1最终结果. 以一个SHA-1报文摘要操作结束, 写下
**                          报文摘要值
** input parameters:		digest    : 报文摘要
**                          context   : SHA-1算法寄存器
** Returned value:			shaSuccess      : 成功
**                          shaNull         : context为空
**                          shaInputTooLong : 输入数据超长
**                          shaStateError   : 获得结果后调用了函数SHA1Update()
** Created by:				NA
** Created Date:			1995
**-------------------------------------------------------------------------------------------------------
** Modified by:				Chenmingji
** Modified date:			2007-04-18
**------------------------------------------------------------------------------------------------------
********************************************************************************************************/
        int SHA1Final(unsigned char Message_Digest[SHA1HashSize], SHA1Context *context)
{
    int i;

    if (!context || !Message_Digest)
    {
        return shaNull;
    }

    if (context->Corrupted)
    {
        return context->Corrupted;
    }

    if (!context->Computed)
    {
        SHA1PadMessage(context);
        for(i=0; i<64; ++i)
        {
            /* message may be sensitive, clear it out */
            context->Message_Block[i] = 0;
        }
        context->Length_Low = 0;    /* and clear length */
        context->Length_High = 0;
        context->Computed = 1;
    }

    for(i = 0; i < SHA1HashSize; ++i)
    {
        Message_Digest[i] = (unsigned char)(context->Intermediate_Hash[i>>2] >> 8 * (3 - (i & 0x03)));
    }

    return shaSuccess;
}

/*********************************************************************************************************
** Function name:			SHA1Update
** Descriptions:			执行一次SHA-1算法
** input parameters:		context    : SHA-1算法寄存器
**                          input      : 输入分组
**                          inputLen   : 输入的分组的长度
** Returned value:			shaSuccess      : 成功
**                          shaNull         : context为空
**                          shaInputTooLong : 输入数据超长
**                          shaStateError   : 获得结果后调用了函数SHA1Update()
** Created by:				NA
** Created Date:			1995
**-------------------------------------------------------------------------------------------------------
** Modified by:				Chenmingji
** Modified date:			2007-04-18
**------------------------------------------------------------------------------------------------------
********************************************************************************************************/
        int SHA1Update(SHA1Context *context, const unsigned char *message_array, unsigned length)
{
    if (!length)
    {
        return shaSuccess;
    }

    if (!context || !message_array)
    {
        return shaNull;
    }

    if (context->Computed)
    {
        context->Corrupted = shaStateError;
        return shaStateError;
    }

    if (context->Corrupted)
    {
         return context->Corrupted;
    }
    while(length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] =
                    (unsigned char)(*message_array & 0xFF);

        context->Length_Low += 8;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            if (context->Length_High == 0)
            {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }

        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }

        message_array++;
    }

    return shaSuccess;
}

/*********************************************************************************************************
** Function name:			SHA1ProcessMessageBlock
** Descriptions:			This function will process the next 512 bits of the 
**                          message stored in the Message_Block array.
** input parameters:		none
** Returned value:			none
** Created by:				NA
** Created Date:			1995
**-------------------------------------------------------------------------------------------------------
** Modified by:				Chenmingji
** Modified date:			2007-04-18
**------------------------------------------------------------------------------------------------------
********************************************************************************************************/
        static void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const unsigned int K[] =    {       /* Constants defined in SHA-1   */
                            0x5A827999,
                            0x6ED9EBA1,
                            0x8F1BBCDC,
                            0xCA62C1D6
                            };
    int           t;               /* Loop counter                */
    unsigned int      temp;              /* Temporary word value        */
    unsigned int      W[80];             /* Word sequence               */
    unsigned int      A, B, C, D, E;     /* Word buffers                */

    /* Initialize the first 16 words in the array W  */
    for(t = 0; t < 16; t++)
    {
        W[t] = context->Message_Block[t * 4] << 24;
        W[t] |= context->Message_Block[t * 4 + 1] << 16;
        W[t] |= context->Message_Block[t * 4 + 2] << 8;
        W[t] |= context->Message_Block[t * 4 + 3];
    }

    for(t = 16; t < 80; t++)
    {
       W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    for(t = 0; t < 20; t++)
    {
        temp =  SHA1CircularShift(5,A) +
                ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;

    context->Message_Block_Index = 0;
}

/*********************************************************************************************************
** Function name:			SHA1PadMessage
** Descriptions:			According to the standard, the message must be padded to 
**                          an even 512 bits.  The first padding bit must be a '1'.
**                          The last 64 bits represent the length of the original 
**                          message.  All bits in between should be 0.  This function
**                          will pad the message according to those rules by filling 
**                          the Message_Block array accordingly.  It will also call 
**                          the ProcessMessageBlock function provided appropriately. 
**                          When it returns, it can be assumed that the message digest
**                          has been computed.
** input parameters:		context    : SHA-1算法寄存器
** Returned value:			none
** Created by:				NA
** Created Date:			1995
**-------------------------------------------------------------------------------------------------------
** Modified by:				Chenmingji
** Modified date:			2007-04-18
**------------------------------------------------------------------------------------------------------
********************************************************************************************************/
        static void SHA1PadMessage(SHA1Context *context)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(context);

        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    context->Message_Block[56] = (unsigned char)(context->Length_High >> 24);
    context->Message_Block[57] = (unsigned char)(context->Length_High >> 16);
    context->Message_Block[58] = (unsigned char)(context->Length_High >> 8);
    context->Message_Block[59] = (unsigned char)(context->Length_High);
    context->Message_Block[60] = (unsigned char)(context->Length_Low >> 24);
    context->Message_Block[61] = (unsigned char)(context->Length_Low >> 16);
    context->Message_Block[62] = (unsigned char)(context->Length_Low >> 8);
    context->Message_Block[63] = (unsigned char)(context->Length_Low);

    SHA1ProcessMessageBlock(context);
}
/*********************************************************************************************************
**                            End Of File
********************************************************************************************************/
