// SPDX-License-Identifier: GPL-2.0
/*
 * swtpm driver for TCG/TIS TPM (trusted platform module).
 * Specifications at www.trustedcomputinggroup.org
 */

#include <common.h>
#include <dm.h>
#include <log.h>
#include <tpm-v2.h>
#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/io.h>
#include <linux/unaligned/be_byteshift.h>
#include "tpm_tis.h"
#include "tpm_internal.h"

enum tis_int_flags {
	TPM_GLOBAL_INT_ENABLE = 0x80000000,
	TPM_INTF_BURST_COUNT_STATIC = 0x100,
	TPM_INTF_CMD_READY_INT = 0x080,
	TPM_INTF_INT_EDGE_FALLING = 0x040,
	TPM_INTF_INT_EDGE_RISING = 0x020,
	TPM_INTF_INT_LEVEL_LOW = 0x010,
	TPM_INTF_INT_LEVEL_HIGH = 0x008,
	TPM_INTF_LOCALITY_CHANGE_INT = 0x004,
	TPM_INTF_STS_VALID_INT = 0x002,
	TPM_INTF_DATA_AVAIL_INT = 0x001,
};

struct tpm_tis_chip_data {
	unsigned int pcr_count;
	unsigned int pcr_select_min;
	unsigned int time_before_first_cmd_ms;
	void __iomem *iobase;
};

static int tpm_tis_read_bytes(struct udevice *udev, u32 addr, u16 len,
			      u8 *result)
{
	struct tpm_tis_chip_data *drv_data = (void *)dev_get_driver_data(udev);

	while (len--)
		*result++ = ioread8(drv_data->iobase + addr);
	return 0;
}

static int tpm_tis_write_bytes(struct udevice *udev, u32 addr, u16 len,
			       const u8 *value)
{
	struct tpm_tis_chip_data *drv_data = (void *)dev_get_driver_data(udev);

	while (len--)
		iowrite8(*value++, drv_data->iobase + addr);
	return 0;
}

static __maybe_unused int tpm_tis_read16(struct udevice *udev, u32 addr,
					 u16 *result)
{
	struct tpm_tis_chip_data *drv_data = (void *)dev_get_driver_data(udev);

	*result = ioread16(drv_data->iobase + addr);
	return 0;
}

static int tpm_tis_read32(struct udevice *udev, u32 addr, u32 *result)
{
	struct tpm_tis_chip_data *drv_data = (void *)dev_get_driver_data(udev);

	*result = ioread32(drv_data->iobase + addr);
	return 0;
}

static int tpm_tis_write32(struct udevice *udev, u32 addr, u32 value)
{
	struct tpm_tis_chip_data *drv_data = (void *)dev_get_driver_data(udev);

	iowrite32(value, drv_data->iobase + addr);
	return 0;
}

static int tpm_tis_get_desc(struct udevice *udev, char *buf, int size)
{
	struct tpm_chip *chip = dev_get_priv(udev);

	if (size < 80)
		return -ENOSPC;

	return snprintf(buf, size,
			"%s v2.0: VendorID 0x%04x, DeviceID 0x%04x, RevisionID 0x%02x [%s]",
			udev->name, chip->vend_dev & 0xFFFF,
			chip->vend_dev >> 16, chip->rid,
			(chip->is_open ? "open" : "closed"));
}

static bool tpm_tis_check_locality(struct udevice *udev, int loc)
{
	struct tpm_chip *chip = dev_get_priv(udev);
	u8 locality;

	tpm_tis_read_bytes(udev, TPM_ACCESS(loc), 1, &locality);
	if ((locality & (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID |
			 TPM_ACCESS_REQUEST_USE)) ==
			 (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) {
		chip->locality = loc;
		return true;
	}

	return false;
}

static int tpm_tis_request_locality(struct udevice *udev, int loc)
{
	struct tpm_chip *chip = dev_get_priv(udev);
	u8 buf = TPM_ACCESS_REQUEST_USE;
	unsigned long start, stop;

	if (tpm_tis_check_locality(udev, loc))
		return 0;

	tpm_tis_write_bytes(udev, TPM_ACCESS(loc), 1, &buf);
	start = get_timer(0);
	stop = chip->timeout_a;
	do {
		if (tpm_tis_check_locality(udev, loc))
			return 0;
		mdelay(TPM_TIMEOUT_MS);
	} while (get_timer(start) < stop);

	return -1;
}

static int tpm_tis_status(struct udevice *udev, u8 *status)
{
	struct tpm_chip *chip = dev_get_priv(udev);

	if (chip->locality < 0)
		return -EINVAL;

	tpm_tis_read_bytes(udev, TPM_STS(chip->locality), 1, status);

	if ((*status & TPM_STS_READ_ZERO)) {
		log_err("TPM returned invalid status\n");
		return -EINVAL;
	}

	return 0;
}

static int tpm_tis_release_locality(struct udevice *udev, int loc)
{
	struct tpm_chip *chip = dev_get_priv(udev);
	u8 buf = TPM_ACCESS_ACTIVE_LOCALITY;
	int ret;

	if (chip->locality < 0)
		return 0;

	ret = tpm_tis_write_bytes(udev, TPM_ACCESS(loc), 1, &buf);
	chip->locality = -1;

	return ret;
}

static int tpm_tis_wait_for_stat(struct udevice *udev, u8 mask,
				 unsigned long timeout, u8 *status)
{
	unsigned long start = get_timer(0);
	unsigned long stop = timeout;
	int ret;

	do {
		mdelay(TPM_TIMEOUT_MS);
		ret = tpm_tis_status(udev, status);
		if (ret)
			return ret;

		if ((*status & mask) == mask)
			return 0;
	} while (get_timer(start) < stop);

	return -ETIMEDOUT;
}

static int tpm_tis_get_burstcount(struct udevice *udev, size_t *burstcount)
{
	struct tpm_chip *chip = dev_get_priv(udev);
	unsigned long start, stop;
	u32 burst;

	if (chip->locality < 0)
		return -EINVAL;

	/* wait for burstcount */
	start = get_timer(0);
	/*
	 * This is the TPMv2 defined timeout. Change this in case you want to
	 * make the driver compatile to TPMv1
	 */
	stop = chip->timeout_a;
	do {
		tpm_tis_read32(udev, TPM_STS(chip->locality), &burst);
		*burstcount = (burst >> 8) & 0xFFFF;
		if (*burstcount)
			return 0;

		mdelay(TPM_TIMEOUT_MS);
	} while (get_timer(start) < stop);

	return -ETIMEDOUT;
}

static int tpm_tis_ready(struct udevice *udev)
{
	struct tpm_chip *chip = dev_get_priv(udev);
	u8 data = TPM_STS_COMMAND_READY;

	/* This will cancel any pending commands */
	return tpm_tis_write_bytes(udev, TPM_STS(chip->locality), 1, &data);
}

static int tpm_tis_send(struct udevice *udev, const u8 *buf, size_t len)
{
	struct tpm_chip *chip = dev_get_priv(udev);
	size_t burstcnt, wr_size, sent = 0;
	u8 data = TPM_STS_GO;
	u8 status;
	int ret;

	if (!chip)
		return -ENODEV;

	ret = tpm_tis_request_locality(udev, 0);
	if (ret < 0)
		return -EBUSY;

	ret = tpm_tis_status(udev, &status);
	if (ret)
		goto release_locality;

	if (!(status & TPM_STS_COMMAND_READY)) {
		ret = tpm_tis_ready(udev);
		if (ret) {
			log_err("Can't cancel previous TPM operation\n");
			goto release_locality;
		}
		ret = tpm_tis_wait_for_stat(udev, TPM_STS_COMMAND_READY,
					    chip->timeout_b, &status);
		if (ret) {
			log_err("TPM not ready\n");
			goto release_locality;
		}
	}

	while (len > 0) {
		ret = tpm_tis_get_burstcount(udev, &burstcnt);
		if (ret)
			goto release_locality;

		wr_size = min(len, burstcnt);
		ret = tpm_tis_write_bytes(udev, TPM_DATA_FIFO(chip->locality),
					  wr_size, buf + sent);
		if (ret < 0)
			goto release_locality;

		ret = tpm_tis_wait_for_stat(udev, TPM_STS_VALID,
					    chip->timeout_c, &status);
		if (ret)
			goto release_locality;

		sent += wr_size;
		len -= wr_size;
		/* make sure the TPM expects more data */
		if (len && !(status & TPM_STS_DATA_EXPECT)) {
			ret = -EIO;
			goto release_locality;
		}
	}

	/*
	 * Make a final check ensuring everything is ok and the TPM expects no
	 * more data
	 */
	ret = tpm_tis_wait_for_stat(udev, TPM_STS_VALID, chip->timeout_c,
				    &status);
	if (ret)
		goto release_locality;

	if (status & TPM_STS_DATA_EXPECT) {
		ret = -EIO;
		goto release_locality;
	}

	ret = tpm_tis_write_bytes(udev, TPM_STS(chip->locality), 1, &data);
	if (ret)
		goto release_locality;

	tpm_tis_release_locality(udev, chip->locality);
	return sent;

release_locality:
	tpm_tis_ready(udev);
	tpm_tis_release_locality(udev, chip->locality);

	return ret;
}

static int tpm_tis_recv_data(struct udevice *udev, u8 *buf, size_t count)
{
	struct tpm_chip *chip = dev_get_priv(udev);
	int size = 0, len, ret;
	size_t burstcnt;
	u8 status;

	while (size < count &&
	       tpm_tis_wait_for_stat(udev, TPM_STS_DATA_AVAIL | TPM_STS_VALID,
				     chip->timeout_c, &status) == 0) {
		ret = tpm_tis_get_burstcount(udev, &burstcnt);
		if (ret)
			return burstcnt;

		len = min_t(int, burstcnt, count - size);
		ret = tpm_tis_read_bytes(udev, TPM_DATA_FIFO(chip->locality),
					 len, buf + size);
		if (ret < 0)
			return ret;

		size += len;
	}

	return size;
}

static int tpm_tis_recv(struct udevice *udev, u8 *buf, size_t count)
{
	struct tpm_chip *chip = dev_get_priv(udev);
	int ret;
	int size, expected;

	if (!chip)
		return -ENODEV;

	if (count < TPM_HEADER_SIZE)
		return -E2BIG;

	ret = tpm_tis_request_locality(udev, 0);
	if (ret < 0)
		return -EBUSY;

	size = tpm_tis_recv_data(udev, buf, TPM_HEADER_SIZE);
	if (size < TPM_HEADER_SIZE) {
		log_err("TPM error, unable to read header\n");
		goto out;
	}

	expected = get_unaligned_be32(buf + TPM_CMD_COUNT_OFFSET);
	if (expected > count) {
		size = -EIO;
		log_warning("Too much data: %d > %zu\n", expected, count);
		goto out;
	}

	size += tpm_tis_recv_data(udev, &buf[TPM_HEADER_SIZE],
				   expected - TPM_HEADER_SIZE);
	if (size < expected) {
		log(LOGC_NONE, LOGL_ERR,
		    "TPM error, unable to read remaining bytes of result\n");
		size = -EIO;
		goto out;
	}

out:
	tpm_tis_ready(udev);
	tpm_tis_release_locality(udev, chip->locality);

	return size;
}

static int tpm_tis_probe(struct udevice *udev)
{
	struct tpm_tis_chip_data *drv_data = (void *)dev_get_driver_data(udev);
	struct tpm_chip_priv *priv = dev_get_uclass_priv(udev);
	struct tpm_chip *chip = dev_get_priv(udev);
	int ret = 0;
	fdt_addr_t ioaddr;
	u32 tmp;
	u64 sz;

	ioaddr = dev_read_addr(udev);
	if (ioaddr == FDT_ADDR_T_NONE)
		return -EINVAL;

	ret = dev_read_u64(udev, "reg", &sz);
	if (ret)
		return -EINVAL;

	drv_data->iobase = ioremap(ioaddr, sz);
	log_info("Remapped TPM2 base: 0x%llx size: 0x%llx\n", ioaddr, sz);

	ret = tpm_tis_request_locality(udev, 0);
	if (ret)
		goto iounmap;

	chip->timeout_a = TIS_SHORT_TIMEOUT_MS;
	chip->timeout_b = TIS_LONG_TIMEOUT_MS;
	chip->timeout_c = TIS_SHORT_TIMEOUT_MS;
	chip->timeout_d = TIS_SHORT_TIMEOUT_MS;
	priv->pcr_count = drv_data->pcr_count;
	priv->pcr_select_min = drv_data->pcr_select_min;

	/* Disable interrupts */
	tpm_tis_read32(udev, TPM_INT_ENABLE(chip->locality), &tmp);
	tmp |= TPM_INTF_CMD_READY_INT | TPM_INTF_LOCALITY_CHANGE_INT |
	       TPM_INTF_DATA_AVAIL_INT | TPM_INTF_STS_VALID_INT;
	tmp &= ~TPM_GLOBAL_INT_ENABLE;
	tpm_tis_write32(udev, TPM_INT_ENABLE(chip->locality), tmp);

	/*
	 * Although the driver probably works with a TPMv1 our Kconfig
	 * limits the driver to TPMv2 only
	 */
	priv->version = TPM_V2;
	tpm_tis_read_bytes(udev, TPM_RID(chip->locality), 1, &chip->rid);
	tpm_tis_read32(udev, TPM_DID_VID(chip->locality), &chip->vend_dev);

	tpm_tis_release_locality(udev, chip->locality);

	return ret;

iounmap:
	iounmap(drv_data->iobase);
	return -EINVAL;
}

static int tpm_tis_remove(struct udevice *udev)
{
	struct tpm_chip *chip = dev_get_priv(udev);
	struct tpm_tis_chip_data *drv_data = (void *)dev_get_driver_data(udev);

	iounmap(drv_data->iobase);
	return tpm_tis_release_locality(udev, chip->locality);
}

static int tpm_tis_cleanup(struct udevice *udev)
{
	struct tpm_chip *chip = dev_get_priv(udev);

	tpm_tis_ready(udev);
	tpm_tis_release_locality(udev, chip->locality);

	return 0;
}

static int tpm_tis_open(struct udevice *udev)
{
	struct tpm_chip *chip = dev_get_priv(udev);
	int ret;

	if (chip->is_open)
		return -EBUSY;

	ret = tpm_tis_request_locality(udev, 0);
	if (!ret)
		chip->is_open = 1;

	return ret;
}

static int tpm_tis_close(struct udevice *udev)
{
	struct tpm_chip *chip = dev_get_priv(udev);
	int ret = 0;

	if (chip->is_open) {
		ret = tpm_tis_release_locality(udev, chip->locality);
		chip->is_open = 0;
	}

	return ret;
}

static const struct tpm_ops tpm_tis_ops = {
	.open		= tpm_tis_open,
	.close		= tpm_tis_close,
	.get_desc	= tpm_tis_get_desc,
	.send		= tpm_tis_send,
	.recv		= tpm_tis_recv,
	.cleanup	= tpm_tis_cleanup,
};

static const struct tpm_tis_chip_data tpm_tis_std_chip_data = {
	.pcr_count = 24,
	.pcr_select_min = 3,
};

static const struct udevice_id tpm_tis_ids[] = {
	{
		.compatible = "tcg,tpm-tis-mmio",
		.data = (ulong)&tpm_tis_std_chip_data,
	},
	{ }
};

U_BOOT_DRIVER(tpm_tis_mmio) = {
	.name   = "tpm_tis_mmio",
	.id     = UCLASS_TPM,
	.of_match = tpm_tis_ids,
	.ops    = &tpm_tis_ops,
	.probe	= tpm_tis_probe,
	.remove	= tpm_tis_remove,
	.priv_auto	= sizeof(struct tpm_chip),
};
