/* SPDX-License-Identifier: GPL-2.0 */

#ifndef HADOS_CRYPTO_UAPI_H
#define HADOS_CRYPTO_UAPI_H

#define BDF_LEN 16

enum hados_crypto_cmd_opcode {
	YS_SEC_ALLOC_CHANNEL = 0x1,
	YS_SEC_FREE_CHANNEL,

	/* hash */
	YS_SEC_SM3 = 0x10,
};

struct ys_sec_ring_info {
	unsigned int id;
	unsigned int size;

	unsigned int hw_mmap_id;
	unsigned int hw_len;

	unsigned int desc_mmap_id;
	unsigned int desc_stride;
	unsigned int desc_len;

	unsigned int data_mmap_id;
	unsigned int data_stride;
	unsigned int data_len;

	unsigned int state_mmap_id;
	unsigned int state_len;

	unsigned int pfid;
	unsigned int vfid;

	void *handle;

	char bdf[BDF_LEN];
};

struct ys_sec_sw_cmd {
	unsigned char opcode;

	union {
		/* for alloc/free channel */
		struct {
			unsigned int nb;
			union {
				struct ys_sec_ring_info *rings;
				unsigned int ids[64];
			};
		};
	};
};

#define YS_SEC_SEND_CMD _IOWR('D', 2, struct ys_sec_sw_cmd)

#endif // HADOS_CRYPTO_UAPI_H
