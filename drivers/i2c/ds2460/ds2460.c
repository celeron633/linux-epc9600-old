/*
 * ds2460.c - Driver for DS2460 clipper chip
 *
 * Copyright (C) 2010 Guangzhou Zhiyuan Electronic Co.,LTD.
 * Written by Liu Jingwen <linux@zlgmcu.com>
 *
 *	Base on at24.c code in Linux kernel
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>
#include <linux/mod_devicetable.h>
#include <linux/log2.h>
#include <linux/bitops.h>
#include <linux/jiffies.h>
#include <linux/i2c.h>
#include <linux/fs.h>
#include <linux/i2c/ds2460.h>
#include <linux/miscdevice.h>                                                                                                 

#include <linux/uaccess.h>

struct ds2460_data {
	struct ds2460_platform_data chip;
	struct memory_accessor macc;
	bool use_smbus;

	/*
	 * Lock protects against activities from other Linux tasks,
	 * but not from changes by other I2C masters.
	 */
	struct mutex lock;
	struct bin_attribute bin;

	u8 *writebuf;
	unsigned write_max;
	unsigned num_addresses;

	/*
	 * Some chips tie up multiple I2C addresses; dummy devices reserve
	 * them for us, and we'll use them with SMBus calls.
	 */
	struct i2c_client *client[];
};

struct ds2460_data *global_ds2460_data;

/*
 * This parameter is to help this driver avoid blocking other drivers out
 * of I2C for potentially troublesome amounts of time. With a 100 kHz I2C
 * clock, one 256 byte read takes about 1/43 second which is excessive;
 * but the 1/170 second it takes at 400 kHz may be quite reasonable; and
 * at 1 MHz (Fm+) a 1/430 second delay could easily be invisible.
 *
 * This value is forced to be a power of two so that writes align on pages.
 */
static unsigned io_limit = 128;
module_param(io_limit, uint, 0);
MODULE_PARM_DESC(io_limit, "Maximum bytes per I/O (default 128)");

/*
 * Specs often allow 5 msec for a page write, sometimes 20 msec;
 * it's important to recover from write timeouts.
 */
static unsigned write_timeout = 25;
module_param(write_timeout, uint, 0);
MODULE_PARM_DESC(write_timeout, "Time (in ms) to try writes (default 25)");

#define DS2460_MAGIC_GET(_magic, _pos)	\
	(((_magic) >> (_pos)) & 0xff)

#define DS2460_DEVICE_MAGIC(_byte_len, _expose_start, _expose_len, _flags)	\
	((_byte_len << 24) | (_expose_start << 16) |	\
	 (_expose_len << 8) | (_flags))

static const struct i2c_device_id ds2460_ids[] = {
	//{ "ds2460", DS2460_DEVICE_MAGIC(248, 0x80, 120, DS2460_FLAG_TAKE8ADDR) },
	{ "ds2460", DS2460_DEVICE_MAGIC(248, 0x96, 18, DS2460_FLAG_TAKE8ADDR) },
	{ /* END OF LIST */ }
};
MODULE_DEVICE_TABLE(i2c, ds2460_ids);

/*-------------------------------------------------------------------------*/

/*
 * This routine supports chips which consume multiple I2C addresses. It
 * computes the addressing information to be used for a given r/w request.
 * Assumes that sanity checks for offset happened at sysfs-layer.
 */
static struct i2c_client *ds2460_translate_offset(struct ds2460_data *ds2460,
		unsigned *offset)
{
	unsigned i;

	if (ds2460->chip.flags & DS2460_FLAG_ADDR16) {
		i = *offset >> 16;
		*offset &= 0xffff;
	} else {
		i = *offset >> 8;
		*offset &= 0xff;
	}

	return ds2460->client[i];
}

static ssize_t ds2460_eeprom_read(struct ds2460_data *ds2460, char *buf,
		unsigned offset, size_t count)
{
	struct i2c_msg msg[2];
	u8 msgbuf[2];
	struct i2c_client *client;
	unsigned long timeout, read_time;
	int status, i;

	memset(msg, 0, sizeof(msg));

	/*
	 * REVISIT some multi-address chips don't rollover page reads to
	 * the next slave address, so we may need to truncate the count.
	 * Those chips might need another quirk flag.
	 *
	 * If the real hardware used four adjacent 24c02 chips and that
	 * were misconfigured as one 24c08, that would be a similar effect:
	 * one "eeprom" file not four, but larger reads would fail when
	 * they crossed certain pages.
	 */

	/*
	 * Slave address and byte offset derive from the offset. Always
	 * set the byte address; on a multi-master board, another master
	 * may have changed the chip's "current" address pointer.
	 */
	client = ds2460_translate_offset(ds2460, &offset);

	if (count > io_limit)
		count = io_limit;

	if (ds2460->use_smbus) {
		/* Smaller eeproms can work given some SMBus extension calls */
		if (count > I2C_SMBUS_BLOCK_MAX)
			count = I2C_SMBUS_BLOCK_MAX;
	} else {
		/*
		 * When we have a better choice than SMBus calls, use a
		 * combined I2C message. Write address; then read up to
		 * io_limit data bytes. Note that read page rollover helps us
		 * here (unlike writes). msgbuf is u8 and will cast to our
		 * needs.
		 */
		i = 0;
		if (ds2460->chip.flags & DS2460_FLAG_ADDR16)
			msgbuf[i++] = offset >> 8;
		msgbuf[i++] = offset;

		msg[0].addr = client->addr;
		msg[0].buf = msgbuf;
		msg[0].len = i;

		msg[1].addr = client->addr;
		msg[1].flags = I2C_M_RD;
		msg[1].buf = buf;
		msg[1].len = count;
	}

	/*
	 * Reads fail if the previous write didn't complete yet. We may
	 * loop a few times until this one succeeds, waiting at least
	 * long enough for one entire page write to work.
	 */
	timeout = jiffies + msecs_to_jiffies(write_timeout);
	do {
		read_time = jiffies;
		if (ds2460->use_smbus) {
			status = i2c_smbus_read_i2c_block_data(client, offset,
					count, buf);
		} else {
			status = i2c_transfer(client->adapter, msg, 2);
			if (status == 2)
				status = count;
		}
		dev_dbg(&client->dev, "read %zu@%d --> %d (%ld)\n",
				count, offset, status, jiffies);

		if (status == count)
			return count;

		/* REVISIT: at HZ=100, this is sloooow */
		msleep(1);
	} while (time_before(read_time, timeout));

	return -ETIMEDOUT;
}

static ssize_t ds2460_read(struct ds2460_data *ds2460,
		char *buf, loff_t off, size_t count)
{
	ssize_t retval = 0;

	if (unlikely(!count))
		return count;

	/*
	 * Read data from chip, protecting against concurrent updates
	 * from this host, but not from other I2C masters.
	 */
	mutex_lock(&ds2460->lock);

	while (count) {
		ssize_t	status;

		status = ds2460_eeprom_read(ds2460, buf, off, count);
		if (status <= 0) {
			if (retval == 0)
				retval = status;
			break;
		}
		buf += status;
		off += status;
		count -= status;
		retval += status;
	}

	mutex_unlock(&ds2460->lock);

	return retval;
}

static ssize_t ds2460_bin_read(struct file *filp, struct kobject *kobj, struct bin_attribute *attr,
		char *buf, loff_t off, size_t count)
{
	struct ds2460_data *ds2460;

	ds2460 = dev_get_drvdata(container_of(kobj, struct device, kobj));

	if (!ds2460) {
		printk("ds2460 pointer is NULL\n");
	}

	off += ds2460->chip.expose_start;

	if (count > ds2460->chip.expose_len)
		count = ds2460->chip.expose_len;

	return ds2460_read(ds2460, buf, off, count);
}

/*
 * Note that if the hardware write-protect pin is pulled high, the whole
 * chip is normally write protected. But there are plenty of product
 * variants here, including OTP fuses and partial chip protect.
 *
 * We only use page mode writes; the alternative is sloooow. This routine
 * writes at most one page.
 */
static ssize_t ds2460_eeprom_write(struct ds2460_data *ds2460, const char *buf,
		unsigned offset, size_t count)
{
	struct i2c_client *client;
	struct i2c_msg msg;
	ssize_t status;
	unsigned long timeout, write_time;
	unsigned next_page;

	/* Get corresponding I2C address and adjust offset */
	client = ds2460_translate_offset(ds2460, &offset);

	/* write_max is at most a page */
	if (count > ds2460->write_max)
		count = ds2460->write_max;

	/* Never roll over backwards, to the start of this page */
	next_page = roundup(offset + 1, ds2460->chip.page_size);
	if (offset + count > next_page)
		count = next_page - offset;

	/* If we'll use I2C calls for I/O, set up the message */
	if (!ds2460->use_smbus) {
		int i = 0;

		msg.addr = client->addr;
		msg.flags = 0;

		/* msg.buf is u8 and casts will mask the values */
		msg.buf = ds2460->writebuf;
		if (ds2460->chip.flags & DS2460_FLAG_ADDR16)
			msg.buf[i++] = offset >> 8;

		msg.buf[i++] = offset;
		memcpy(&msg.buf[i], buf, count);
		msg.len = i + count;
	}

	/*
	 * Writes fail if the previous one didn't complete yet. We may
	 * loop a few times until this one succeeds, waiting at least
	 * long enough for one entire page write to work.
	 */
	timeout = jiffies + msecs_to_jiffies(write_timeout);
	do {
		write_time = jiffies;
		if (ds2460->use_smbus) {
			status = i2c_smbus_write_i2c_block_data(client,
					offset, count, buf);
			if (status == 0)
				status = count;
		} else {
			status = i2c_transfer(client->adapter, &msg, 1);
			if (status == 1)
				status = count;
		}
		dev_dbg(&client->dev, "write %zu@%d --> %zd (%ld)\n",
				count, offset, status, jiffies);

		if (status == count)
			return count;

		/* REVISIT: at HZ=100, this is sloooow */
		msleep(1);
	} while (time_before(write_time, timeout));

	return -ETIMEDOUT;
}

static ssize_t ds2460_write(struct ds2460_data *ds2460, const char *buf, loff_t off,
			  size_t count)
{
	ssize_t retval = 0;

	if (unlikely(!count))
		return count;

	/*
	 * Write data to chip, protecting against concurrent updates
	 * from this host, but not from other I2C masters.
	 */
	mutex_lock(&ds2460->lock);

	while (count) {
		ssize_t	status;

		status = ds2460_eeprom_write(ds2460, buf, off, count);
		if (status <= 0) {
			if (retval == 0)
				retval = status;
			break;
		}
		buf += status;
		off += status;
		count -= status;
		retval += status;
	}

	mutex_unlock(&ds2460->lock);

	return retval;
}

static ssize_t ds2460_bin_write(struct file *filp, struct kobject *kobj, struct bin_attribute *attr,
		char *buf, loff_t off, size_t count)
{
	struct ds2460_data *ds2460;

	ds2460 = dev_get_drvdata(container_of(kobj, struct device, kobj));
	if (!ds2460) {
		printk("ds2460 pointer is NULL\n");
	}

	off += ds2460->chip.expose_start;

	if (count > ds2460->chip.expose_len)
		count = ds2460->chip.expose_len;

	return ds2460_write(ds2460, buf, off, count);
}

/*-------------------------------------------------------------------------*/

/*
 * This lets other kernel code access the eeprom data. For example, it
 * might hold a board's Ethernet address, or board-specific calibration
 * data generated on the manufacturing floor.
 */

static ssize_t ds2460_macc_read(struct memory_accessor *macc, char *buf,
			 off_t offset, size_t count)
{
	struct ds2460_data *ds2460 = container_of(macc, struct ds2460_data, macc);

	return ds2460_read(ds2460, buf, offset, count);
}

static ssize_t ds2460_macc_write(struct memory_accessor *macc, const char *buf,
			  off_t offset, size_t count)
{
	struct ds2460_data *ds2460 = container_of(macc, struct ds2460_data, macc);

	return ds2460_write(ds2460, buf, offset, count);
}

/*-------------------------------------------------------------------------*/

/*
 * The whole eeprom of ds2460 can be accesed by those two functions
 */

ssize_t ds2460_read_generic(u8 *buf, loff_t addr, unsigned len)
{
	struct ds2460_data *ds2460 = global_ds2460_data;

	if (!ds2460)
		return -ENODEV;

	return ds2460_read(ds2460, buf, addr, len);
}
EXPORT_SYMBOL(ds2460_read_generic);

ssize_t ds2460_write_generic(u8 *buf, loff_t addr, unsigned len)
{
	struct ds2460_data *ds2460 = global_ds2460_data;

	if (!ds2460)
		return -ENODEV;

	return ds2460_write(ds2460, buf, addr, len);
}
EXPORT_SYMBOL(ds2460_write_generic);

/*-------------------------------------------------------------------------*/

static ssize_t sysinfo_read(struct file *file,  char *buf,
		                          size_t count, loff_t *ppos)
{
	int ret = 0;
	int nbyte;
	u8 *temp_buf;
	struct ds2460_data *ds2460 = global_ds2460_data;

	if (!ds2460) {
		ret = -ENODEV;
		goto out;
	}
/*
	if (count > ds2460->chip.expose_len)
		count = ds2460->chip.expose_len;

	*ppos += ds2460->chip.expose_start;
*/
    if (count > 120)
        count = 120;
    *ppos += 80;

	temp_buf = kzalloc(count, GFP_KERNEL);
	if (!temp_buf) {
		ret = -ENOMEM;
		goto out;
	}

	/* read info from ds2460 */
	nbyte = ds2460_read(ds2460, temp_buf, *ppos, count);
	if (nbyte < 0) {
		ret = -EFAULT;
		goto free_mem;
	}

	ret = copy_to_user(buf, temp_buf, nbyte);
	if (ret < 0) {
		ret = -EFAULT;
		goto free_mem;
	}

free_mem:
	kfree(temp_buf);
out:
	return ret; 
}

static const struct file_operations sysinfo_fops = { 
	.owner  = THIS_MODULE,
	.read   = sysinfo_read,
};

static struct miscdevice sysinfo_misc = { 
	.minor  = MISC_DYNAMIC_MINOR,
	.name   = "sysinfo",
	.fops   = &sysinfo_fops,

};

/*-------------------------------------------------------------------------*/

static int ds2460_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct ds2460_platform_data chip;
	bool writable;
	bool use_smbus = false;
	struct ds2460_data *ds2460;
	int err;
	unsigned i, num_addresses;
	kernel_ulong_t magic;

	if (client->dev.platform_data) {
		chip = *(struct ds2460_platform_data *)client->dev.platform_data;
	} else {
		if (!id->driver_data) {
			err = -ENODEV;
			goto err_out;
		}
		magic = id->driver_data;
		chip.byte_len = DS2460_MAGIC_GET(magic, 24);
		chip.expose_start = DS2460_MAGIC_GET(magic, 16);
		chip.expose_len = DS2460_MAGIC_GET(magic, 8);
		chip.flags = DS2460_MAGIC_GET(magic, 0);
		/*
		 * This is slow, but we can't know all eeproms, so we better
		 * play safe. Specifying custom eeprom-types via platform_data
		 * is recommended anyhow.
		 */
		chip.page_size = 1;

		chip.setup = NULL;
		chip.context = NULL;
	}

	if (!is_power_of_2(chip.byte_len))
		dev_warn(&client->dev,
			"byte_len looks suspicious (no power of 2)!\n");
	if (!is_power_of_2(chip.page_size))
		dev_warn(&client->dev,
			"page_size looks suspicious (no power of 2)!\n");

	/* Use I2C operations unless we're stuck with SMBus extensions. */
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		if (chip.flags & DS2460_FLAG_ADDR16) {
			err = -EPFNOSUPPORT;
			goto err_out;
		}
		if (!i2c_check_functionality(client->adapter,
				I2C_FUNC_SMBUS_READ_I2C_BLOCK)) {
			err = -EPFNOSUPPORT;
			goto err_out;
		}
		use_smbus = true;
	}

	if (chip.flags & DS2460_FLAG_TAKE8ADDR)
		num_addresses = DIV_ROUND_UP(chip.byte_len, 256);
	else
		num_addresses =	DIV_ROUND_UP(chip.byte_len,
			(chip.flags & DS2460_FLAG_ADDR16) ? 65536 : 256);

	ds2460 = kzalloc(sizeof(struct ds2460_data) +
		num_addresses * sizeof(struct i2c_client *), GFP_KERNEL);
	if (!ds2460) {
		err = -ENOMEM;
		goto err_out;
	}

	mutex_init(&ds2460->lock);
	ds2460->use_smbus = use_smbus;
	ds2460->chip = chip;
	ds2460->num_addresses = num_addresses;

	/*
	 * Export the EEPROM bytes through sysfs, since that's convenient.
	 * By default, only root should see the data (maybe passwords etc)
	 */
	ds2460->bin.attr.name = "eeprom";
	ds2460->bin.attr.mode = chip.flags & DS2460_FLAG_IRUGO ? S_IRUGO : S_IRUSR;
	ds2460->bin.read = ds2460_bin_read;
	ds2460->bin.size = chip.expose_len;

	ds2460->macc.read = ds2460_macc_read;

	writable = !(chip.flags & DS2460_FLAG_READONLY);
	if (writable) {
		if (!use_smbus || i2c_check_functionality(client->adapter,
				I2C_FUNC_SMBUS_WRITE_I2C_BLOCK)) {

			unsigned write_max = chip.page_size;

			ds2460->macc.write = ds2460_macc_write;

			ds2460->bin.write = ds2460_bin_write;
			ds2460->bin.attr.mode |= S_IWUSR;

			if (write_max > io_limit)
				write_max = io_limit;
			if (use_smbus && write_max > I2C_SMBUS_BLOCK_MAX)
				write_max = I2C_SMBUS_BLOCK_MAX;
			ds2460->write_max = write_max;

			/* buffer (data + address at the beginning) */
			ds2460->writebuf = kmalloc(write_max + 2, GFP_KERNEL);
			if (!ds2460->writebuf) {
				err = -ENOMEM;
				goto err_struct;
			}
		} else {
			dev_warn(&client->dev,
				"cannot write due to controller restrictions.");
		}
	}

	ds2460->client[0] = client;

	/* use dummy devices for multiple-address chips */
	for (i = 1; i < num_addresses; i++) {
		ds2460->client[i] = i2c_new_dummy(client->adapter,
					client->addr + i);
		if (!ds2460->client[i]) {
			dev_err(&client->dev, "address 0x%02x unavailable\n",
					client->addr + i);
			err = -EADDRINUSE;
			goto err_clients;
		}
	}

#if 1
	err = sysfs_create_bin_file(&client->dev.kobj, &ds2460->bin);
	if (err) {
		printk("sysfs_create_bin_file error\n");
		goto err_clients;
	}
#endif
	i2c_set_clientdata(client, ds2460);
	global_ds2460_data = ds2460;

	dev_info(&client->dev, "%zu byte %s EEPROM %s\n",
		ds2460->bin.size, client->name,
		writable ? "(writable)" : "(read-only)");
	dev_dbg(&client->dev,
		"page_size %d, num_addresses %d, write_max %d%s\n",
		chip.page_size, num_addresses,
		ds2460->write_max,
		use_smbus ? ", use_smbus" : "");

	/* export data to kernel code */
	if (chip.setup)
		chip.setup(&ds2460->macc, chip.context);

	return 0;

err_clients:
	for (i = 1; i < num_addresses; i++)
		if (ds2460->client[i])
			i2c_unregister_device(ds2460->client[i]);

	kfree(ds2460->writebuf);
err_struct:
	kfree(ds2460);
err_out:
	dev_dbg(&client->dev, "probe error %d\n", err);
	return err;
}

static int __devexit ds2460_remove(struct i2c_client *client)
{
	struct ds2460_data *ds2460;
	int i;

	ds2460 = i2c_get_clientdata(client);
	sysfs_remove_bin_file(&client->dev.kobj, &ds2460->bin);

	for (i = 1; i < ds2460->num_addresses; i++)
		i2c_unregister_device(ds2460->client[i]);

	kfree(ds2460->writebuf);
	kfree(ds2460);
	i2c_set_clientdata(client, NULL);
	return 0;
}

/*-------------------------------------------------------------------------*/

static struct i2c_driver ds2460_driver = {
	.driver = {
		.name = "ds2460",
		.owner = THIS_MODULE,
	},
	.probe = ds2460_probe,
	.remove = __devexit_p(ds2460_remove),
	.id_table = ds2460_ids,
};

static int __init ds2460_init(void)
{
	int ret;

	io_limit = rounddown_pow_of_two(io_limit);

	ret = i2c_add_driver(&ds2460_driver);
	if (ret >= 0)
		ret = misc_register(&sysinfo_misc);

	return ret;
}
module_init(ds2460_init);

static void __exit ds2460_exit(void)
{
	misc_deregister(&sysinfo_misc);
	i2c_del_driver(&ds2460_driver);
}
module_exit(ds2460_exit);

MODULE_DESCRIPTION("Driver for DS2460 Clipper Chip");
MODULE_AUTHOR("Liu Jingwen <linux@zlgmcu.com>");
MODULE_LICENSE("GPL");
