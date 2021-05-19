#include <linux/ioctl.h>

/* mmc_ioc_cmd.opcode */
#define MMC_SEND_EXT_CSD                 8
#define MMC_READ_MULTIPLE_BLOCK         18
#define MMC_WRITE_MULTIPLE_BLOCK        25

#define IOCTL(fd, request, ...) ioctl_emu((fd), (request), ##__VA_ARGS__)
#define mmc_ioc_cmd_set_data(ic, ptr) ic.data_ptr = (__u64)(unsigned long) ptr
#define MMC_CMD23_ARG_REL_WR    (1 << 31) /* CMD23 reliable write */

/* Emulated rel_wr_sec_c value (reliable write size, *256 bytes) */
#define EMU_RPMB_REL_WR_SEC_C	1
/* Emulated rpmb_size_mult value (RPMB size, *128 kB) */
#define EMU_RPMB_SIZE_MULT	2

#define EMU_RPMB_SIZE_BYTES	(EMU_RPMB_SIZE_MULT * 128 * 1024)

struct mmc_ioc_cmd {
	/* Implies direction of data.  true = write, false = read */
	int write_flag;

	/* Application-specific command.  true = precede with CMD55 */
	int is_acmd;

	uint32_t opcode;
	uint32_t arg;
	uint32_t response[4];  /* CMD response */
	unsigned int flags;
	unsigned int blksz;
	unsigned int blocks;

	/*
	 * Sleep at least postsleep_min_us useconds, and at most
	 * postsleep_max_us useconds *after* issuing command.  Needed for
	 * some read commands for which cards have no other way of indicating
	 * they're ready for the next command (i.e. there is no equivalent of
	 * a "busy" indicator for read operations).
	 */
	unsigned int postsleep_min_us;
	unsigned int postsleep_max_us;

	/*
	 * Override driver-computed timeouts.  Note the difference in units!
	 */
	unsigned int data_timeout_ns;
	unsigned int cmd_timeout_ms;

	/*
	 * For 64-bit machines, the next member, ``__u64 data_ptr``, wants to
	 * be 8-byte aligned.  Make sure this struct is the same size when
	 * built for 32-bit.
	 */
	uint32_t __pad;

	/* DAT buffer */
	uint32_t data_ptr;
};
#define MMC_BLOCK_MAJOR		179
#define MMC_IOC_CMD _IOWR(MMC_BLOCK_MAJOR, 0, struct mmc_ioc_cmd)

/* Request */
struct rpmb_req {
	uint16_t cmd;
#define RPMB_CMD_DATA_REQ      0x00
#define RPMB_CMD_GET_DEV_INFO  0x01
	uint16_t dev_id;
	uint16_t block_count;
	/* Optional data frames (rpmb_data_frame) follow */
};
#define RPMB_REQ_DATA(req) ((void *)((struct rpmb_req *)(req) + 1))

/* Response to device info request */
struct rpmb_dev_info {
	uint8_t cid[16];
	uint8_t rpmb_size_mult;	/* EXT CSD-slice 168: RPMB Size */
	uint8_t rel_wr_sec_c;	/* EXT CSD-slice 222: Reliable Write Sector */
				/*                    Count */
	uint8_t ret_code;
#define RPMB_CMD_GET_DEV_INFO_RET_OK     0x00
#define RPMB_CMD_GET_DEV_INFO_RET_ERROR  0x01
};
/* mmc_ioc_cmd.flags */
#define MMC_RSP_PRESENT (1 << 0)
#define MMC_RSP_136     (1 << 1)        /* 136 bit response */
#define MMC_RSP_CRC     (1 << 2)        /* Expect valid CRC */
#define MMC_RSP_OPCODE  (1 << 4)        /* Response contains opcode */

#define MMC_RSP_R1      (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)

#define MMC_CMD_ADTC    (1 << 5)        /* Addressed data transfer command */


/* Emulated eMMC device state */
struct rpmb_emu {
	uint8_t buf[EMU_RPMB_SIZE_BYTES];
	size_t size;
	uint8_t key[32];
	bool key_set;
	uint8_t nonce[16];
	uint32_t write_counter;
	struct {
		uint16_t msg_type;
		uint16_t op_result;
		uint16_t address;
	} last_op;
};

/*
 * This structure is shared with OP-TEE and the MMC ioctl layer.
 * It is the "data frame for RPMB access" defined by JEDEC, minus the
 * start and stop bits.
 */
struct rpmb_data_frame {
	uint8_t stuff_bytes[196];
	uint8_t key_mac[32];
	uint8_t data[256];
	uint8_t nonce[16];
	uint32_t write_counter;
	uint16_t address;
	uint16_t block_count;
	uint16_t op_result;
#define RPMB_RESULT_OK				0x00
#define RPMB_RESULT_GENERAL_FAILURE		0x01
#define RPMB_RESULT_AUTH_FAILURE		0x02
#define RPMB_RESULT_ADDRESS_FAILURE		0x04
#define RPMB_RESULT_AUTH_KEY_NOT_PROGRAMMED	0x07
	uint16_t msg_type;
#define RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM		0x0001
#define RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ	0x0002
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE		0x0003
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_READ		0x0004
#define RPMB_MSG_TYPE_REQ_RESULT_READ			0x0005
#define RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM		0x0100
#define RPMB_MSG_TYPE_RESP_WRITE_COUNTER_VAL_READ	0x0200
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE		0x0300
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_READ		0x0400
};

uint32_t rpmb_process_request_emu(void *req, size_t req_size,
                                  void *rsp, size_t rsp_size);
