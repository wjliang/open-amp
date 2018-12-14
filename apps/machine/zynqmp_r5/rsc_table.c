/*
 * Copyright (c) 2014, Mentor Graphics Corporation
 * All rights reserved.
 * Copyright (c) 2015 Xilinx, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* This file populates resource table for BM remote
 * for use by the Linux Master */

#include <openamp/open_amp.h>
#include "rsc_table.h"

/* Place resource table in special ELF section */
#define __section_t(S)          __attribute__((__section__(#S)))
#define __resource              __section_t(.resource_table)

#define RPMSG_IPU_C0_FEATURES        1

/* VirtIO rpmsg device id */
#define VIRTIO_ID_RPMSG_             7

/* Remote supports Name Service announcement */
#define VIRTIO_RPMSG_F_NS           0

#define NUM_VRINGS                  0x02
#define VRING_ALIGN                 0x1000
#define RING_TX                     0x3ED40000
#define RING_RX                     0x3ED44000
#define VRING_SIZE                  256

#define NUM_TABLE_ENTRIES           3

#define IOMMU_READ   (1 << 0)
#define IOMMU_WRITE  (1 << 1)
#define IOMMU_CACHE  (1 << 2)
#define IOMMU_NOEXEC (1 << 3)
#define IOMMU_MMIO   (1 << 4)

struct remote_resource_table __resource resources = {
	/* Version */
	1,

	/* NUmber of table entries */
	NUM_TABLE_ENTRIES,
	/* reserved fields */
	{0, 0,},

	/* Offsets of rsc entries */
	{
	 offsetof(struct remote_resource_table, ddr),
	 offsetof(struct remote_resource_table, rpu_glbl_cntr),
	 offsetof(struct remote_resource_table, rpmsg_vdev),
	 },

	/* firmware DDR memory */
	{
	 RSC_CARVEOUT, 0x3ed00000, 0x3ed00000, 0x40000,
	 IOMMU_READ | IOMMU_WRITE, 0, "fw-ddr",
	},
	/* RPU global control registers */
	{
	 RSC_DEVMEM, 0xFF9A0000, 0xFF9A0000, 0x1000,
	 IOMMU_READ | IOMMU_WRITE, 0, "rpu-cntr",
	},
	/* Virtio device entry */
	{
	 RSC_VDEV, VIRTIO_ID_RPMSG_, 0, RPMSG_IPU_C0_FEATURES, 0, 0, 0,
	 NUM_VRINGS, {0, 0},
	 },

	/* Vring rsc entry - part of vdev rsc entry */
	{FW_RSC_U32_ADDR_ANY, VRING_ALIGN, VRING_SIZE, 1, 0},
	{FW_RSC_U32_ADDR_ANY, VRING_ALIGN, VRING_SIZE, 2, 0},
};

void *get_resource_table (int rsc_id, int *len)
{
	(void) rsc_id;
	*len = sizeof(resources);
	return &resources;
}

