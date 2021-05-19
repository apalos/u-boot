// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020 Linaro Limited
 */

#include <common.h>
#include <dm.h>
#include <hexdump.h>
#include <log.h>
#include <tee.h>
#include <mmc.h>
#include <dm/device_compat.h>

#include "optee_msg.h"
#include "optee_private.h"
#include "sha2.h"
#include "hmac_sha2.h"
#include "rpmb_emu.h"

static struct rpmb_emu rpmb_emu = {
	.size = EMU_RPMB_SIZE_BYTES
};

static struct rpmb_emu *mem_for_fd(int fd)
{
	static int sfd = -1;

	if (sfd == -1)
		sfd = fd;
	if (sfd != fd) {
		printf("Emulating more than 1 RPMB partition is not supported\n");
		return NULL;
	}

	return &rpmb_emu;
}

#if (DEBUGLEVEL >= TRACE_FLOW)
static void dump_blocks(size_t startblk, size_t numblk, uint8_t *ptr,
			bool to_mmc)
{
	char msg[100] = { 0 };
	size_t i = 0;

	for (i = 0; i < numblk; i++) {
		snprintf(msg, sizeof(msg), "%s MMC block %zu",
			 to_mmc ? "Write" : "Read", startblk + i);
		//print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, ptr, 256);
		ptr += 256;
	}
}
#else
static void dump_blocks(size_t startblk, size_t numblk, uint8_t *ptr,
			bool to_mmc)
{
	(void)startblk;
	(void)numblk;
	(void)ptr;
	(void)to_mmc;
}
#endif

#define CUC(x) ((const unsigned char *)(x))
static void hmac_update_frm(hmac_sha256_ctx *ctx, struct rpmb_data_frame *frm)
{
	hmac_sha256_update(ctx, CUC(frm->data), 256);
	hmac_sha256_update(ctx, CUC(frm->nonce), 16);
	hmac_sha256_update(ctx, CUC(&frm->write_counter), 4);
	hmac_sha256_update(ctx, CUC(&frm->address), 2);
	hmac_sha256_update(ctx, CUC(&frm->block_count), 2);
	hmac_sha256_update(ctx, CUC(&frm->op_result), 2);
	hmac_sha256_update(ctx, CUC(&frm->msg_type), 2);
}

static bool is_hmac_valid(struct rpmb_emu *mem, struct rpmb_data_frame *frm,
		   size_t nfrm)
{
	uint8_t mac[32] = { 0 };
	size_t i = 0;
	hmac_sha256_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));

	if (!mem->key_set) {
		printf("Cannot check MAC (key not set)\n");
		return false;
	}

	hmac_sha256_init(&ctx, mem->key, sizeof(mem->key));
	for (i = 0; i < nfrm; i++, frm++)
		hmac_update_frm(&ctx, frm);
	frm--;
	hmac_sha256_final(&ctx, mac, 32);

	if (memcmp(mac, frm->key_mac, 32)) {
		printf("Invalid MAC\n");
		return false;
	}
	return true;
}

static uint16_t gen_msb1st_result(uint8_t byte)
{
	return (uint16_t)byte << 8;
}

static uint16_t compute_hmac(struct rpmb_emu *mem, struct rpmb_data_frame *frm,
			     size_t nfrm)
{
	size_t i = 0;
	hmac_sha256_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));

	if (!mem->key_set) {
		printf("Cannot compute MAC (key not set)\n");
		return gen_msb1st_result(RPMB_RESULT_AUTH_KEY_NOT_PROGRAMMED);
	}

	hmac_sha256_init(&ctx, mem->key, sizeof(mem->key));
	for (i = 0; i < nfrm; i++, frm++)
		hmac_update_frm(&ctx, frm);
	frm--;
	hmac_sha256_final(&ctx, frm->key_mac, 32);

	return gen_msb1st_result(RPMB_RESULT_OK);
}

static uint16_t ioctl_emu_mem_transfer(struct rpmb_emu *mem,
				       struct rpmb_data_frame *frm,
				       size_t nfrm, int to_mmc)
{
	size_t start = mem->last_op.address * 256;
	size_t size = nfrm * 256;
	size_t i = 0;
	uint8_t *memptr = NULL;

	if (start > mem->size || start + size > mem->size) {
		printf("Transfer bounds exceeed emulated memory\n");
		return gen_msb1st_result(RPMB_RESULT_ADDRESS_FAILURE);
	}
	if (to_mmc && !is_hmac_valid(mem, frm, nfrm))
		return gen_msb1st_result(RPMB_RESULT_AUTH_FAILURE);

	//printf("Transferring %zu 256-byte data block%s %s MMC (block offset=%zu)",
	     //nfrm, (nfrm > 1) ? "s" : "", to_mmc ? "to" : "from", start / 256);
	for (i = 0; i < nfrm; i++) {
		memptr = mem->buf + start + i * 256;
		if (to_mmc) {
			memcpy(memptr, frm[i].data, 256);
			mem->write_counter++;
			frm[i].write_counter = htonl(mem->write_counter);
			frm[i].msg_type =
				htons(RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE);
		} else {
			memcpy(frm[i].data, memptr, 256);
			frm[i].msg_type =
				htons(RPMB_MSG_TYPE_RESP_AUTH_DATA_READ);
			frm[i].address = htons(mem->last_op.address);
			frm[i].block_count = nfrm;
			memcpy(frm[i].nonce, mem->nonce, 16);
		}
		frm[i].op_result = gen_msb1st_result(RPMB_RESULT_OK);
	}
	dump_blocks(mem->last_op.address, nfrm, mem->buf + start, to_mmc);

	if (!to_mmc)
		compute_hmac(mem, frm, nfrm);

	return gen_msb1st_result(RPMB_RESULT_OK);
}

static void ioctl_emu_get_write_result(struct rpmb_emu *mem,
				       struct rpmb_data_frame *frm)
{
	frm->msg_type =	htons(RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE);
	frm->op_result = mem->last_op.op_result;
	frm->address = htons(mem->last_op.address);
	frm->write_counter = htonl(mem->write_counter);
	compute_hmac(mem, frm, 1);
}

static uint16_t ioctl_emu_setkey(struct rpmb_emu *mem,
				 struct rpmb_data_frame *frm)
{
	if (mem->key_set) {
		printf("Key already set\n");
		return gen_msb1st_result(RPMB_RESULT_GENERAL_FAILURE);
	}
	print_hex_dump_bytes("Setting Key:", DUMP_PREFIX_OFFSET, frm->key_mac,
			     32);
	memcpy(mem->key, frm->key_mac, 32);
	mem->key_set = true;

	return gen_msb1st_result(RPMB_RESULT_OK);
}

static void ioctl_emu_get_keyprog_result(struct rpmb_emu *mem,
					 struct rpmb_data_frame *frm)
{
	frm->msg_type =
		htons(RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM);
	frm->op_result = mem->last_op.op_result;
}

static void ioctl_emu_read_ctr(struct rpmb_emu *mem,
			       struct rpmb_data_frame *frm)
{
	printf("Reading counter\n");
	frm->msg_type = htons(RPMB_MSG_TYPE_RESP_WRITE_COUNTER_VAL_READ);
	frm->write_counter = htonl(mem->write_counter);
	memcpy(frm->nonce, mem->nonce, 16);
	frm->op_result = compute_hmac(mem, frm, 1);
}

static uint32_t read_cid(uint16_t dev_id, uint8_t *cid)
{
	/* Taken from an actual eMMC chip */
	static const uint8_t test_cid[] = {
		/* MID (Manufacturer ID): Micron */
		0xfe,
		/* CBX (Device/BGA): BGA */
		0x01,
		/* OID (OEM/Application ID) */
		0x4e,
		/* PNM (Product name) "MMC04G" */
		0x4d, 0x4d, 0x43, 0x30, 0x34, 0x47,
		/* PRV (Product revision): 4.2 */
		0x42,
		/* PSN (Product serial number) */
		0xc8, 0xf6, 0x55, 0x2a,
		/*
		 * MDT (Manufacturing date):
		 * June, 2014
		 */
		0x61,
		/* (CRC7 (0xA) << 1) | 0x1 */
		0x15
	};

	(void)dev_id;
	memcpy(cid, test_cid, sizeof(test_cid));

	return TEE_SUCCESS;
}

static void ioctl_emu_set_ext_csd(uint8_t *ext_csd)
{
	ext_csd[168] = EMU_RPMB_SIZE_MULT;
	ext_csd[222] = EMU_RPMB_REL_WR_SEC_C;
}

/* A crude emulation of the MMC ioctls we need for RPMB */
static int ioctl_emu(int fd, unsigned long request, ...)
{
	struct mmc_ioc_cmd *cmd = NULL;
	struct rpmb_data_frame *frm = NULL;
	uint16_t msg_type = 0;
	struct rpmb_emu *mem = mem_for_fd(fd);
	va_list ap;

	if (request != MMC_IOC_CMD) {
		printf("Unsupported ioctl: 0x%lx\n", request);
		return -1;
	}
	if (!mem)
		return -1;

	va_start(ap, request);
	cmd = va_arg(ap, struct mmc_ioc_cmd *);
	va_end(ap);

	switch (cmd->opcode) {
	case MMC_SEND_EXT_CSD:
		ioctl_emu_set_ext_csd((uint8_t *)(uintptr_t)cmd->data_ptr);
		break;

	case MMC_WRITE_MULTIPLE_BLOCK:
		frm = (struct rpmb_data_frame *)(uintptr_t)cmd->data_ptr;
		msg_type = ntohs(frm->msg_type);

		switch (msg_type) {
		case RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM:
			mem->last_op.msg_type = msg_type;
			mem->last_op.op_result = ioctl_emu_setkey(mem, frm);
			break;

		case RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE:
			mem->last_op.msg_type = msg_type;
			mem->last_op.address = ntohs(frm->address);
			mem->last_op.op_result =
					ioctl_emu_mem_transfer(mem, frm,
							       cmd->blocks, 1);
			break;

		case RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ:
		case RPMB_MSG_TYPE_REQ_AUTH_DATA_READ:
			memcpy(mem->nonce, frm->nonce, 16);
			mem->last_op.msg_type = msg_type;
			mem->last_op.address = ntohs(frm->address);
			break;
		default:
			break;
		}
		break;

	case MMC_READ_MULTIPLE_BLOCK:
		frm = (struct rpmb_data_frame *)(uintptr_t)cmd->data_ptr;
		msg_type = ntohs(frm->msg_type);

		switch (mem->last_op.msg_type) {
		case RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM:
			ioctl_emu_get_keyprog_result(mem, frm);
			break;

		case RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE:
			ioctl_emu_get_write_result(mem, frm);
			break;

		case RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ:
			ioctl_emu_read_ctr(mem, frm);
			break;

		case RPMB_MSG_TYPE_REQ_AUTH_DATA_READ:
			ioctl_emu_mem_transfer(mem, frm, cmd->blocks, 0);
			break;

		default:
			printf("Unexpected\n");
			break;
		}
		break;

	default:
		printf("Unsupported ioctl opcode 0x%08x\n", cmd->opcode);
		return -1;
	}

	return 0;
}

static int mmc_rpmb_fd(uint16_t dev_id)
{
	(void)dev_id;

	/* Any value != -1 will do in test mode */
	return 0;
}

static int mmc_fd(uint16_t dev_id)
{
	(void)dev_id;

	return 0;
}

static void close_mmc_fd(int fd)
{
	(void)fd;
}

/*
 * Extended CSD Register is 512 bytes and defines device properties
 * and selected modes.
 */
static uint32_t read_ext_csd(int fd, uint8_t *ext_csd)
{
	int st = 0;
	struct mmc_ioc_cmd cmd = {
		.blksz = 512,
		.blocks = 1,
		.flags = MMC_RSP_R1 | MMC_CMD_ADTC,
		.opcode = MMC_SEND_EXT_CSD,
	};

	mmc_ioc_cmd_set_data(cmd, ext_csd);

	st = IOCTL(fd, MMC_IOC_CMD, &cmd);
	if (st < 0)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static uint32_t rpmb_data_req(int fd, struct rpmb_data_frame *req_frm,
			      size_t req_nfrm, struct rpmb_data_frame *rsp_frm,
			      size_t rsp_nfrm)
{
	int st = 0;
	size_t i = 0;
	uint16_t msg_type = ntohs(req_frm->msg_type);
	struct mmc_ioc_cmd cmd = {
		.blksz = 512,
		.blocks = req_nfrm,
		.data_ptr = (uintptr_t)req_frm,
		.flags = MMC_RSP_R1 | MMC_CMD_ADTC,
		.opcode = MMC_WRITE_MULTIPLE_BLOCK,
		.write_flag = 1,
	};

	for (i = 1; i < req_nfrm; i++) {
		if (req_frm[i].msg_type != msg_type) {
			printf("All request frames shall be of the same type\n");
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	//printf("Req: %zu frame(s) of type 0x%04x", req_nfrm, msg_type);
	//printf("Rsp: %zu frame(s)", rsp_nfrm);

	switch(msg_type) {
	case RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM:
	case RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE:
		if (rsp_nfrm != 1) {
			printf("Expected only one response frame\n");
			return TEE_ERROR_BAD_PARAMETERS;
		}

		/* Send write request frame(s) */
		cmd.write_flag |= MMC_CMD23_ARG_REL_WR;
		/*
		 * Black magic: tested on a HiKey board with a HardKernel eMMC
		 * module. When postsleep values are zero, the kernel logs
		 * random errors: "mmc_blk_ioctl_cmd: Card Status=0x00000E00"
		 * and ioctl() fails.
		 */
		cmd.postsleep_min_us = 20000;
		cmd.postsleep_max_us = 50000;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEE_ERROR_GENERIC;
		cmd.postsleep_min_us = 0;
		cmd.postsleep_max_us = 0;

		/* Send result request frame */
		memset(rsp_frm, 0, 1);
		rsp_frm->msg_type = htons(RPMB_MSG_TYPE_REQ_RESULT_READ);
		cmd.data_ptr = (uintptr_t)rsp_frm;
		cmd.write_flag &= ~MMC_CMD23_ARG_REL_WR;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEE_ERROR_GENERIC;

		/* Read response frame */
		cmd.opcode = MMC_READ_MULTIPLE_BLOCK;
		cmd.write_flag = 0;
		cmd.blocks = rsp_nfrm;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEE_ERROR_GENERIC;
		break;

	case RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ:
		if (rsp_nfrm != 1) {
			printf("Expected only one response frame\n");
			return TEE_ERROR_BAD_PARAMETERS;
		}
//#if __GNUC__ > 6
		//__attribute__((fallthrough));
//#endif

	case RPMB_MSG_TYPE_REQ_AUTH_DATA_READ:
		if (req_nfrm != 1) {
			printf("Expected only one request frame\n");
			return TEE_ERROR_BAD_PARAMETERS;
		}

		/* Send request frame */
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEE_ERROR_GENERIC;

		/* Read response frames */
		cmd.data_ptr = (uintptr_t)rsp_frm;
		cmd.opcode = MMC_READ_MULTIPLE_BLOCK;
		cmd.write_flag = 0;
		cmd.blocks = rsp_nfrm;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEE_ERROR_GENERIC;
		break;

	default:
		printf("Unsupported message type: %d", msg_type);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static uint32_t rpmb_get_dev_info(uint16_t dev_id, struct rpmb_dev_info *info)
{
	int fd = 0;
	uint32_t res = 0;
	uint8_t ext_csd[512] = { 0 };

	res = read_cid(dev_id, info->cid);
	if (res != TEE_SUCCESS)
		return res;

	fd = mmc_fd(dev_id);
	if (fd < 0)
		return TEE_ERROR_BAD_PARAMETERS;

	res = read_ext_csd(fd, ext_csd);
	if (res != TEE_SUCCESS)
		goto err;

	info->rel_wr_sec_c = ext_csd[222];
	info->rpmb_size_mult = ext_csd[168];
	info->ret_code = RPMB_CMD_GET_DEV_INFO_RET_OK;

err:
	close_mmc_fd(fd);
	return res;
}


/*
 * req is one struct rpmb_req followed by one or more struct rpmb_data_frame
 * rsp is either one struct rpmb_dev_info or one or more struct rpmb_data_frame
 */
uint32_t rpmb_process_request_emu(void *req, size_t req_size,
				  void *rsp, size_t rsp_size)
{
	struct rpmb_req *sreq = req;
	size_t req_nfrm = 0;
	size_t rsp_nfrm = 0;
	uint32_t res = 0;
	int fd = 0;

	if (req_size < sizeof(*sreq))
		return TEE_ERROR_BAD_PARAMETERS;

	switch (sreq->cmd) {
	case RPMB_CMD_DATA_REQ:
		req_nfrm = (req_size - sizeof(struct rpmb_req)) / 512;
		rsp_nfrm = rsp_size / 512;
		fd = mmc_rpmb_fd(sreq->dev_id);
		if (fd < 0)
			return TEE_ERROR_BAD_PARAMETERS;
		res = rpmb_data_req(fd, RPMB_REQ_DATA(req), req_nfrm, rsp,
				    rsp_nfrm);
		break;

	case RPMB_CMD_GET_DEV_INFO:
		if (req_size != sizeof(struct rpmb_req) ||
		    rsp_size != sizeof(struct rpmb_dev_info)) {
			printf("Invalid req/rsp size");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		res = rpmb_get_dev_info(sreq->dev_id,
					(struct rpmb_dev_info *)rsp);
		break;

	default:
		printf("Unsupported RPMB command: %d", sreq->cmd);
		res = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	return res;
}
