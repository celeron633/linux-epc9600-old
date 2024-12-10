/****************************************Copyright (c)**************************************************
**                               Guangzou ZLG-MCU Development Co.,LTD.
**                                      graduate school
**                                 http://www.zlgmcu.com
**
**--------------File Info-------------------------------------------------------------------------------
** File name:			main.c
** Last modified Date:  2004-09-16
** Last Version:		1.0
** Descriptions:		The main() function example template
**
**------------------------------------------------------------------------------------------------------
** Created by:			Chenmingji
** Created date:		2004-09-16
** Version:				1.0
** Descriptions:		The original version
**
**------------------------------------------------------------------------------------------------------
** Modified by:         Chenxibing
** Modified date:       2010-01-12
** Version:             V1.1
** Descriptions:        For LPC3250
**
********************************************************************************************************/

#include "config.h"
#include "SHA-1.h"
#include "sha1.h"
#include <linux/i2c/ds2460.h>

#include <asm/uaccess.h>
#include <linux/delay.h>

static const uint8 CRC_TAB[256] = {  
                          0,  94, 188, 226,  97,  63, 221, 131, 194, 156, 126,  32, 163, 253,  31,  65,
                        157, 195,  33, 127, 252, 162,  64,  30,  95,   1, 227, 189,  62,  96, 130, 220,  
                         35, 125, 159, 193,  66,  28, 254, 160, 225, 191,  93,   3, 128, 222,  60,  98, 
                        190, 224,   2,  92, 223, 129,  99,  61, 124,  34, 192, 158,  29,  67, 161, 255,
                         70,  24, 250, 164,  39, 121, 155, 197, 132, 218,  56, 102, 229, 187,  89,   7,
                        219, 133, 103,  57, 186, 228,   6,  88,  25,  71, 165, 251, 120,  38, 196, 154,
                        101,  59, 217, 135,   4,  90, 184, 230, 167, 249,  27,  69, 198, 152, 122,  36,
                        248, 166,  68,  26, 153, 199,  37, 123,  58, 100, 134, 216,  91,   5, 231, 185,
                        140, 210,  48, 110, 237, 179,  81,  15,  78,  16, 242, 172,  47, 113, 147, 205,
                         17,  79, 173, 243, 112,  46, 204, 146, 211, 141, 111,  49, 178, 236,  14,  80,
                        175, 241,  19,  77, 206, 144, 114,  44, 109,  51, 209, 143,  12,  82, 176, 238,
                         50, 108, 142, 208,  83,  13, 239, 177, 240, 174,  76,  18, 145, 207,  45, 115,
                        202, 148, 118,  40, 171, 245,  23,  73,   8,  86, 180, 234, 105,  55, 213, 139,
                         87,   9, 235, 181,  54, 104, 138, 212, 149, 203,  41, 119, 244, 170,  72,  22,
                         233,183,  85,  11, 136, 214,  52, 106,  43, 117, 151, 201,  74,  20, 246, 168,
                         116, 42, 200, 150,  21,  75, 169, 247, 182, 232,  10,  84, 215, 137, 107,  53
                    };

unsigned char ucRandom[64];		/* gloabal for randoms */
/*********************************************************************************************************

1. password get fom DS2460

*********************************************************************************************************/


#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif 


#define  DS2460_ADDR			0x80	
#define  DS2460_SPACE_SIZE		256


/*********************************************************************************************************
** Function name:		crc8
** Descriptions:		caculate crc8£¬expression: x^8 + X^5 + X^4 + x^0
** input parameters:        Fcs : inittal value for crcr£¬in general is 0x0¡£
**                          cp  : data
**                          n   : data length
** Returned value:	          value of crc
** Created by:				Chenmingji
** Created Date:            2007-06-19
**-------------------------------------------------------------------------------------------------------
** Modified by:
** Modified date:
**------------------------------------------------------------------------------------------------------
********************************************************************************************************/
uint8 crc8(uint8 Fcs, uint8 *p, unsigned int n)
{
    uint8 crc;

    crc = Fcs;
    do
    { 
        crc = CRC_TAB[(crc ^ (*p))];
        p++;
    } while(--n != 0);
 
    return (crc);
}



uint32 CrpOK;
/*********************************************************************************************************
** Function name:			CrpEncryptPswToPsw
** Descriptions:			Read Data from DS2460, then get password
** input parameters:        uint8 *ucEnPsw: password
**                          uint8 len:	length of password, fixed at 8
** Returned value:			TRUE: success;      FALSE: faulse
** Created by:				
** Created Date:
**-------------------------------------------------------------------------------------------------------
** Modified by:		Chenxibing
** Modified date:	2010-01-12
**------------------------------------------------------------------------------------------------------
********************************************************************************************************/
int CrpEncryptPswToPsw(uint8 *ucEnPsw, uint8 len)
{
   SHA1Context reg;
   uint8 mac_buf[8];
   uint8 usr_buf[64];
   uint8 sn_buf[8];
   uint8 CRP[16];
   int i;
   
   /* Get MAC, user_data and SN, use for password */
//   read_from_ds2460(mac_buf, 0x80,    8);
//   read_from_ds2460(usr_buf, 0x80+48, 64);
//   read_from_ds2460(sn_buf,  0xF0,    8);

   ds2460_read_generic(mac_buf, 0x80,    8);
   ds2460_read_generic(usr_buf, 0x80+48, 64);
   ds2460_read_generic(sn_buf,  0xF0,    8);

   SHA1Init(&reg);
	
   SHA1Update(&reg, mac_buf, 8);  	//MAC
   SHA1Update(&reg, usr_buf, 64);  	//user_data
   SHA1Update(&reg, sn_buf, 8);		//SN
   SHA1Final(CRP, &reg);
#if  1 /* WinCE,Base0 = 20 */
   CRP[8] ^= CRP[10];
   CRP[13] ^= CRP[9];
   CRP[11] ^= CRP[2];
   CRP[15] ^= CRP[3];
   CRP[14] ^= CRP[1];
   CRP[12] ^= CRP[0];
   CRP[6] ^= CRP[4];
   CRP[7] ^= CRP[5];
#else
   CRP[8]  ^= CRP[4];
   CRP[11] ^= CRP[5];
   CRP[14] ^= CRP[2];
   CRP[15] ^= CRP[3];
   CRP[6]  ^= CRP[1];
   CRP[7]  ^= CRP[0];
   CRP[12] ^= CRP[9];
   CRP[13] ^= CRP[10];
#endif

    for(i=0; i<8; i++) {
        *ucEnPsw++ = CRP[i];
    }	
   return TRUE;
}

/*********************************************************************************************************
** Function name:
** Descriptions:
** input parameters:
** 
** Returned value:
** Created by:				
** Created Date:
**-------------------------------------------------------------------------------------------------------
** Modified by:
** Modified date:
**------------------------------------------------------------------------------------------------------
********************************************************************************************************/
uint8 MacCmpA_ForUserType(uint8 *Thismac)
{
    
    return TRUE;   
}



/*********************************************************************************************************
** Function name:			MacCmp
**
** Descriptions:			none
**
** input parameters:		none
** Returned value:			none
**         
** Used global variables:	None
** Calling modules:			None
**
** Created by:				Chenmingji
** Created Date:			2004/02/02
**-------------------------------------------------------------------------------------------------------
** Modified by:
** Modified date:
**------------------------------------------------------------------------------------------------------
********************************************************************************************************/
uint8 MacCmpA(uint8 *Thismac)
{
    int i,j;
    uint8 *tp;
    uint8 Out[64];
    uint8 CRP[8];

    /* code for verify ID */
    if (Thismac[0] != 0x3c) {
        return FALSE;
    }
    if (crc8(0, Thismac, 8) != 0)  {
        return FALSE;
    }
	
	CrpEncryptPswToPsw(CRP, 8);			/* decrypt */

    /* get randoms, MUST be SAME as the random in CrpTask */
    tp = Out;
    i = 64;
	j = 0;
    do {
        *tp++ = ucRandom[j];
        j++;
    } while (--i != 0);

    return MyMacComputation(Thismac, Out, CRP);
}

/*********************************************************************************************************
** Function name:			MacCmpB
** Descriptions:			none
** input parameters:		none
** Returned value:			none
** Created by:				Chenmingji
** Created Date:			2006.7.12
**-------------------------------------------------------------------------------------------------------
** Modified by:             MingYuan Zheng
** Modified date:           2007.10.27
**------------------------------------------------------------------------------------------------------
** Note:                    DS2460's Slave address is 0x80 
********************************************************************************************************/
uint8 MacCmpB(uint8 *SrcIn, uint8 *SrcOut)
{
    unsigned int rt;
    int i;

    rt = 0;
    i = 20;
    do
    {
        rt = rt | (((*SrcIn++) ^ (*SrcOut++)));
    } while (--i != 0);
    return (uint8)rt;
}


/*********************************************************************************************************
** Function name:			CrpTask
** Descriptions:			Encrypt Task
** input parameters:		none
** Returned value:			none
** Created by:				Chenmingji
** Created Date:			2006.7.12
**-------------------------------------------------------------------------------------------------------
** Modified by:             MingYuan Zheng
** Modified date:           2007.10.27
**------------------------------------------------------------------------------------------------------
** Modified by:             Chenxibing
** Modified date:           2010-01-12
********************************************************************************************************/

int CrpTask(BOOL bUSerType, BOOL bCrpFirstPhase, UCHAR *pRandom, DWORD dwRandomlen)
{
    uint8 SrcOut[64];
    uint8 SrcIn[20], I2cMac[20];
    int32 ret;
    uint8 sv_sn[8];

   volatile unsigned int i; 


        /***********************************************************************/
        /*	get randoms, MUST be SAME as it in MacCmpA                     */
        /***********************************************************************/
		memcpy(ucRandom, pRandom, 64);
		memcpy(SrcOut, pRandom, 64);

#if DS2460_DEBUG_EN
        printk("Random is:\n");
        for (i = 0; i < 64; i++) {
	        printk("%x ", SrcOut[i]);
        }
        printk("\r\n");
#endif
    
        /************************************************************************/
        /*  1.  write randoms to ds2460 , sub addr 0x00                         */          
        /************************************************************************/
#if 1
        //if ( write_to_ds2460(SrcOut, 0x00, 64) == -ENOSYS) {
        if ( ds2460_write_generic(SrcOut, 0x00, 64) == -ENOSYS) {
	        printk("send Random to ds2460 fail, try again.\r\n");
			//if (write_to_ds2460(SrcOut, 0x00, 64) == -ENOSYS) {
			if (ds2460_write_generic(SrcOut, 0x00, 64) == -ENOSYS) {
				printk("send Random to ds2460 fail.\r\n");
				return FALSE;
			}			
	    }
#endif
#if DS2460_DEBUG_EN
        printk("send Random to ds2460 OK.\r\n");
#endif    

        /************************************************************************/
        /*  2.  ds2460 start caculate                                           */          
        /************************************************************************/
        SrcOut[0] = 0x94;                                          /* command			*/
        //if (write_to_ds2460(SrcOut, 0x5C, 1) == -ENOSYS) {
        if (ds2460_write_generic(SrcOut, 0x5C, 1) == -ENOSYS) {
	        printk("send cmd to ds2460 fail.\r\n");
            return FALSE;
	    }

        mdelay(10); //waiting caculate complete
    /************************************************************************/
    /*  3.  Get SN of ds2460 , Sun-Addr 0xF0                                */          
    /************************************************************************/
	//ret = read_from_ds2460(SrcIn, 0xF0, 8); //read ID
	ret = ds2460_read_generic(SrcIn, 0xF0, 8); //read ID
	if (ret == -ENOSYS) {
		printk("read number from crp-chip fail, 0x%x\r\n", ret);
        return FALSE;
	}

#if DS2460_DEBUG_EN
    printk("ds2460 number is:\n");
    for (i = 0; i < 8; i++)
    {
        printk("%x ", SrcIn[i]);
    }
    printk("\r\n");
#endif

    /************************************************************************/
    /*  4. host caculate verify code                                         */          
    /************************************************************************/
    if (bUSerType == TRUE) 
    {
        if (MacCmpA_ForUserType(SrcIn) == FALSE) {              /* crypt for users*/
            CrpOK = 0;
    		printk("MacCmpA(SrcIn) fail (user).\r\n");
            return FALSE;
        }    
    }
    else if (MacCmpA(SrcIn) == FALSE) {                         /* crypt for system */   
        CrpOK = 0;
		printk("MacCmpA(SrcIn) fail.\r\n");
        return FALSE;
    }

#if DS2460_DEBUG_EN
    printk("MacCmpA(SrcIn) OK.\r\n");
    printk("calculate data is:");
    for (i = 0; i < 20; i++) {
        printk("%x ", SrcIn[i]);
    }
    printk("\r\n");
#endif

    /************************************************************************/
    /*  5. read verify code in ds2460 , Sub-addr 0x40                       */          
    /************************************************************************/
	//if (read_from_ds2460(I2cMac, 0x40, 20) == -ENOSYS) {
	if (ds2460_read_generic(I2cMac, 0x40, 20) == -ENOSYS) {
		printk("read check data from crp-chip fail.\r\n");
        return FALSE;
	}
#if DS2460_DEBUG_EN
    printk("read check data is:");
    for (i = 0; i < 20; i++) {
       printk("%x ", I2cMac[i]);
    }
    printk("\r\n");
#endif
    /************************************************************************/
    /*  6. compare two verify codes                                         */          
    /************************************************************************/
    i = MacCmpB(SrcIn, I2cMac);

	if (i == 0) {
#if DS2460_DEBUG_EN
		printk("MacCmpB return OK.");
#endif
		return TRUE;
	}

	printk("MacCmpB return fail.");
	return FALSE;
}
/*********************************************************************************************************
**                            End Of File
********************************************************************************************************/
