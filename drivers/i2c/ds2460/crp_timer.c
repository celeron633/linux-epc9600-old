/*                                                     
 * By Chenxibing(Abing) chenxibing1980@gmail.com 
 */                                                    
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/timer.h>

#include <linux/reboot.h>   
#include <linux/signal.h>   

#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/version.h>

#include "config.h"

MODULE_LICENSE("Dual BSD/GPL");

static struct task_struct *_task;
struct timer_list epc_crp;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
DECLARE_MUTEX(crp_sem);
#else
DEFINE_SEMAPHORE(crp_sem);
#endif

extern unsigned char ucRandom[64] ;

static void epc_crp_timeout(unsigned long arg)
{
    up(&crp_sem);
	//mod_timer(&epc_crp, jiffies + 30*HZ);
	mod_timer(&epc_crp, jiffies + 50*HZ);
}

static void epc_encrypt(unsigned long arg)
{
    int i;

    while(1) {
        down(&crp_sem); //请求获取信号量
        get_random_bytes(ucRandom, 64);

        if (CrpTask(0, 0, ucRandom, 64) == FALSE) {
            printk("CRP2 ERROR happened!\n");
            //arm_pm_restart('h', NULL);
            machine_restart(NULL);
			//machine_halt();
        }
    }
}

static int epc_crp_init(void)
{
#if 1
    get_random_bytes(ucRandom, 64);
    if (CrpTask(0, 0, ucRandom, 64) == FALSE) {
        printk("CRP2 ERROR happened!\n");
        machine_restart(NULL);
    }
#endif
    _task = kthread_run(epc_encrypt, NULL, "zlt_encryptd"); 
//	epc_feed_wdt();
#if 1
	init_timer(&epc_crp);
	epc_crp.function = &epc_crp_timeout;
	//epc_crp.expires = jiffies + 30*HZ;
	epc_crp.expires = jiffies + (ucRandom[0]+60)*HZ;
	add_timer(&epc_crp);
#endif
	//epc_feed_wdt();

	return 0;
}

module_init(epc_crp_init);

