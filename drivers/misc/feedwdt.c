#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <asm/io.h>
#include <asm/mach/arch.h>
#include <mach/hardware.h>
#include <mach/gpio.h>

struct timer_list epc_watchdog;

void epc_feed_wdt(void)
{
	gpio_direction_output(65, 0);
	ndelay(2);
	gpio_direction_output(65, 1);
}
EXPORT_SYMBOL(epc_feed_wdt);

static void epc_watchdog_timeout(unsigned long arg)
{
	//printk("timer out!\n");
	epc_feed_wdt();	
	mod_timer(&epc_watchdog, jiffies + 1*HZ/4);
}

static int epc_timer_init(void)
{	
	epc_feed_wdt();
	printk("wdt feed timer start!!\n");
	init_timer(&epc_watchdog);
	epc_watchdog.function = &epc_watchdog_timeout;
	epc_watchdog.expires = jiffies + 1*HZ/4;
	add_timer(&epc_watchdog);
	epc_feed_wdt();

	return 0;
}

//static void epc_timer_exit(void)
//{
//	printk(KERN_ALERT "Goodbye, cruel world\n");
//}

subsys_initcall(epc_timer_init);
//module_init(epc_timer_init);
//module_exit(epc_timer_exit);

MODULE_LICENSE("Dual BSD/GPL");

