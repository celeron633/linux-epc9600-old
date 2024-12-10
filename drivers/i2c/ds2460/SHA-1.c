/****************************************Copyright (c)**************************************************
**                               Guangzou ZLG-MCU Development Co.,LTD.
**                                      graduate school
**                                 http://www.zlgmcu.com
**
**--------------File Info-------------------------------------------------------------------------------
** File name:			sha-1.c
** Last modified Date:	2005-11-21
** Last Version:		1.01
** Descriptions:		The software realization of the calculate way SHA-1
**
**------------------------------------------------------------------------------------------------------
** Created by:			zouchao
** Created date:		2005-10-28
** Version:				1.0
** Descriptions:		The original version
**
**------------------------------------------------------------------------------------------------------
** Modified by:			Chenmingji
** Modified date:		2005-11-21
** Version:				1.01
** Descriptions:		Change to one function
**
**------------------------------------------------------------------------------------------------------
** Modified by: 
** Modified date:
** Version:	
** Descriptions: 
**
********************************************************************************************************/
#include	"config.h"
//#include "typedef.h"

#define IN_SHA

/*********************************************************************************************************
** Function name:			MacComputation
**
** Descriptions:			The software realization of the calculate way SHA-1
**
**
** input parameters:		Handle:Not use
**                          Rt:    Mac Data
**                          Set:   In Put Message
**                          Secret:Password
** Returned value:			TRUE:  OK
**                          FALSE: Not OK
**
** Created by:				Chenmingji
** Created Date:			2005-11-21
**-------------------------------------------------------------------------------------------------------
** Modified by:
** Modified date:
**------------------------------------------------------------------------------------------------------
********************************************************************************************************/

        uint8 MyMacComputation(uint8 *Rt, uint8 *Set, uint8 *Secret)
{
	uint32 temp, *ip;
	uint32 MacA, MacB, MacC, MacD, MacE, mFt;
    uint32 Wtt[80];
    uint32 Mt[16];
    unsigned int i;
    

    if ((Rt == NULL)    ||
        (Set == NULL)   ||
        (Secret == NULL))
    {
        return FALSE;
    }

    ip = Mt;
    i = 16;
	do
	{
        temp = (*Set++) << 24;
        temp |= ((*Set++) << 16);
        temp |= ((*Set++) << 8);
        temp |= (*Set++);
        *ip++ = temp;
	} while (--i != 0);
	
	Mt[15] = 0x01B8;
	Mt[14] = 0x00;
	Mt[13] = ((Mt[13] & 0xffffff00) | 0x80);

    temp = (*Secret++) << 24;
    temp |= ((*Secret++) << 16);
    temp |= ((*Secret++) << 8);
    temp |= (*Secret++);
    Mt[0] = temp;

    temp = (*Secret++) << 24;
    temp |= ((*Secret++) << 16);
    temp |= ((*Secret++) << 8);
    temp |= (*Secret++);
    Mt[12] = temp;    

	
	MacA = 0x67452301;
	MacB = 0xEFCDAB89;
	MacC = 0x98BADCFE;
	MacD = 0x10325476;
	MacE = 0xC3D2E1F0;
/*------------------------------------------------------------------------------------------------------
	Wtt [i] =Mt[i]			(0  ≤ i ≤ 15)
			=S1(Wtt[i-3] ^ Wtt[i-8] ^ Wtt[i-14] ^ Wtt[i-16])	(16 ≤ i ≤ 79)	
	S1表示：左环移一位			 	
--------------------------------------------------------------------------------------------------------*/
	for (i = 0; i < 16; i++)
	{
	    Wtt[i] = Mt[i];
	}
	for (i = 16; i < 80; i++)
	{
	    temp = (Wtt[i - 3] ^ Wtt[i - 8] ^ Wtt[i - 14] ^ Wtt[i - 16]);
		Wtt[i] = (((temp >> 31) & 0x00000001) | ((temp << 1) & 0xfffffffe));
	}	
	
	for (i = 0; i < 20; i++)
	{
	    mFt = ((MacB & MacC) | ((~MacB) & MacD));
		temp = (((MacA & 0x07ffffff) << 5) | ((MacA & 0xf8000000) >> 27)) + mFt + Wtt[i] + 0x5A827999 + MacE;
		MacE = MacD;
		MacD = MacC;
		MacC = ((MacB << 30) & 0xc0000000) | ((MacB >> 2 ) & 0x3fffffff);	//B左环移30位
		MacB = MacA;
		MacA = temp;

	}

	for (; i < 40; i++)
	{
	    mFt = MacB ^ MacC ^ MacD;
		temp = (((MacA & 0x07ffffff) << 5) | ((MacA & 0xf8000000) >> 27)) + mFt + Wtt[i] + 0x6ED9EBA1 + MacE;
		MacE = MacD;
		MacD = MacC;
		MacC = ((MacB << 30) & 0xc0000000) | ((MacB >> 2 ) & 0x3fffffff);	//B左环移30位
		MacB = MacA;
		MacA = temp;
	}

	for (; i < 60; i++)
	{
	    mFt = ((MacB & MacC) | (MacB & MacD) | (MacC & MacD));
		temp = (((MacA & 0x07ffffff) << 5) | ((MacA & 0xf8000000) >> 27)) + mFt + Wtt[i] + 0x8F1BBCDC + MacE;
		MacE = MacD;
		MacD = MacC;
		MacC = ((MacB << 30) & 0xc0000000) | ((MacB >> 2 ) & 0x3fffffff);	//B左环移30位
		MacB = MacA;
		MacA = temp;
	}

	for (; i < 80; i++)
	{
	    mFt = (MacB ^ MacC ^ MacD);
		temp = (((MacA & 0x07ffffff) << 5) | ((MacA & 0xf8000000) >> 27)) + mFt + Wtt[i] + 0xCA62C1D6 + MacE;
		MacE = MacD;
		MacD = MacC;
		MacC = ((MacB << 30) & 0xc0000000) | ((MacB >> 2 ) & 0x3fffffff);	//B左环移30位
		MacB = MacA;
		MacA = temp;
	}
					

/*-----------------------------------------------
转换成硬件件MAC Output buffer寄存器相对应的格式。   													
-------------------------------------------------*/
    *Rt++ = (uint8)MacE;
    *Rt++ = (uint8)(MacE >> 8);
    *Rt++ = (uint8)(MacE >> 16);
    *Rt++ = (uint8)(MacE >> 24);

    *Rt++ = (uint8)MacD;
    *Rt++ = (uint8)(MacD >> 8);
    *Rt++ = (uint8)(MacD >> 16);
    *Rt++ = (uint8)(MacD >> 24);

    *Rt++ = (uint8)MacC;
    *Rt++ = (uint8)(MacC >> 8);
    *Rt++ = (uint8)(MacC >> 16);
    *Rt++ = (uint8)(MacC >> 24);

    *Rt++ = (uint8)MacB;
    *Rt++ = (uint8)(MacB >> 8);
    *Rt++ = (uint8)(MacB >> 16);
    *Rt++ = (uint8)(MacB >> 24);

    *Rt++ = (uint8)MacA;
    *Rt++ = (uint8)(MacA >> 8);
    *Rt++ = (uint8)(MacA >> 16);
    *Rt   = (uint8)(MacA >> 24);
    return TRUE;
}

/*********************************************************************************************************
**                            End Of File
********************************************************************************************************/
