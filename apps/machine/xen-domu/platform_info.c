/*
 * Copyright (c) 2014, Mentor Graphics Corporation
 * All rights reserved.
 * Copyright (c) 2018 Xilinx, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**************************************************************************
 * FILE NAME
 *
 *       platform_info.c
 *
 * DESCRIPTION
 *
 *       This file define platform specific data and implements APIs to set
 *       platform specific information for OpenAMP.
 *
 **************************************************************************/

#include <openamp/rpmsg_virtio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "platform_info.h"
#include "rsc_table.h"

#define PROC_ID_VDEV_SLAVE  0
#define PROC_ID_VDEV_MASTER 1

#define SHMEM_FILE         "/dev/xen_mem"
#define SHMEM_SIZE         0x80000UL

#define RSC_MEM_PA  0x0UL
#define SHARED_BUF_PA   0x20000UL
#define SHARED_BUF_SIZE 0x40000UL

/* Shared memory DMA buffer ioctl macro */
#define TEST_GET_FD 0

/* External functions */
extern int init_system(void);
extern void cleanup_system(void);

struct remoteproc_priv {
	const char *shm_file;
	int shm_size;
	int shm_fd;
	int shm_dma_buf_fd;
	void *shm_va;
	struct metal_io_region shm_io;
	struct remoteproc_mem shm;
};

static struct remoteproc_priv rproc_priv = {
	.shm_file = SHMEM_FILE,
	.shm_size = SHMEM_SIZE,
};

static int xen_rproc_block_read(struct metal_io_region *io,
				unsigned long offset,
				void *restrict dst,
				memory_order order,
				int len)
{
	void *src = metal_io_virt(io, offset);

	(void)order;
	(void)memcpy(dst, src, len);
	return len;
}

static int xen_rproc_block_write(struct metal_io_region *io,
				 unsigned long offset,
				 const void *restrict src,
				 memory_order order,
				 int len)
{
	void *dst = metal_io_virt(io, offset);

	(void)order;
	(void)memcpy(dst, src, len);
	return len;
}

static void xen_rproc_block_set(struct metal_io_region *io,
				unsigned long offset,
				unsigned char value,
				memory_order order,
				int len)
{
	void *dst = metal_io_virt(io, offset);

	(void)order;
	(void)memset(dst, value, len);
	return;
}

static struct metal_io_ops xen_rproc_io_ops = {
	.write = NULL,
	.read = NULL,
	.block_read = xen_rproc_block_read,
	.block_write = xen_rproc_block_write,
	.block_set = xen_rproc_block_set,
	.close = NULL,
};

static struct remoteproc *
xen_rproc_init(struct remoteproc *rproc,
	       struct remoteproc_ops *ops, void *arg)
{
	struct remoteproc_priv *prproc = arg;
	struct remoteproc_mem *shm;
	int ret;

	if (!rproc || !prproc)
		return NULL;
	rproc->priv = prproc;
	prproc->shm_fd = -1;
	/* Open XEN shared memory device */
#if 1
	ret = open(prproc->shm_file, 0);
	if (ret < 0) {
		printf("Failed to init rproc, failed to open shm %s.\n",
		       prproc->shm_file);
		return NULL;
	}
	prproc->shm_fd = ret;

	/* Get XEN shared memory DMA buffer file descriptor */
	ret = ioctl(prproc->shm_fd, TEST_GET_FD, &prproc->shm_dma_buf_fd);
	if (ret < 0) {
		printf("Failed to init rproc, failed to get DMA buffer fd.\n");
		goto err;
	}

	/* mmap XEN shared DMA memory */
	prproc->shm_va = mmap(NULL, prproc->shm_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, prproc->shm_dma_buf_fd, 0);
	if (prproc->shm_va == MAP_FAILED) {
		printf("Failed to init rproc, failed to mmap DMA buf.\n");
		goto err;
	}
#else
	prproc->shm_va = malloc(prproc->shm_size);
	if (prproc->shm_va == NULL)
		return NULL;
#endif
	printf("%s, shared mem va %p, %d\n", __func__, prproc->shm_va, prproc->shm_size);
	shm = &prproc->shm;
	shm->pa = 0;
	shm->da = 0;
	shm->size = prproc->shm_size;
	metal_io_init(&prproc->shm_io, prproc->shm_va, &shm->pa,
		      prproc->shm_size, -1, 0, &xen_rproc_io_ops);
	shm->io = &prproc->shm_io;
	metal_list_add_tail(&rproc->mems, &shm->node);

	rproc->ops = ops;
	printf("%s succeeded\n", __func__);
	return rproc;

err:
	if (prproc->shm_fd >= 0)
		close(prproc->shm_fd);
	return NULL;
}

static void xen_rproc_remove(struct remoteproc *rproc)
{
	struct remoteproc_priv *prproc;

	if (!rproc)
		return;
	prproc = rproc->priv;

	/* Close shared memory */
	if (prproc->shm_fd >= 0) {
		/* Unmap shared memory DMA buffer */
		munmap(prproc->shm_va, prproc->shm_size);
		close(prproc->shm_fd);
	}
#if 0
	free(prproc->shm_va);
#endif
}

static int xen_rproc_notify(struct remoteproc *rproc, uint32_t id)
{
	/* Do nothing */
	(void)rproc;
	(void)id;
	return 0;
}

static struct remoteproc_ops xen_rproc_ops = {
	.init = xen_rproc_init,
	.remove = xen_rproc_remove,
	.notify = xen_rproc_notify,
	.start = NULL,
	.stop = NULL,
	.shutdown = NULL,
};

static struct remoteproc rproc_inst;

/* RPMsg virtio shared buffer pool */
static struct rpmsg_virtio_shm_pool shpool;

static struct remoteproc *
platform_create_proc(int proc_index, int rsc_index)
{
	struct remoteproc_priv *prproc;
	void *rsc_table, *rsc_table_shm;
	int rsc_size;
	int ret;
	metal_phys_addr_t pa;

	(void)proc_index;
	rsc_table = get_resource_table(rsc_index, &rsc_size);

	prproc = &rproc_priv;

	/* Initialize remoteproc instance */
	if (!remoteproc_init(&rproc_inst, &xen_rproc_ops, prproc))
		return NULL;

	/* Mmap resource table */
	pa = RSC_MEM_PA;
	rsc_table_shm = remoteproc_mmap(&rproc_inst, &pa, NULL, rsc_size,
					0, &rproc_inst.rsc_io);

	/* Setup resource table
	 * This step can be done out of the application.
	 * Assume vdev slave is the one to start first and it will
	 * initialize the resource table */
	printf("%s rsc_shm va: %p.\n", __func__, rsc_table_shm);
	if (proc_index == PROC_ID_VDEV_SLAVE)
		memcpy(rsc_table_shm, rsc_table, rsc_size);

	/* parse resource table to remoteproc */
	ret = remoteproc_set_rsc_table(&rproc_inst, rsc_table_shm, rsc_size);
	if (ret) {
		printf("Failed to set resource table to remoteproc\r\n");
		remoteproc_remove(&rproc_inst);
		return NULL;
	}
	printf("Initialize remoteproc successfully.\r\n");
	return &rproc_inst;
}


int platform_init(int argc, char *argv[], void **platform)
{
	unsigned long proc_id = 0;
	unsigned long rsc_id = 0;
	struct remoteproc *rproc;

	if (!platform) {
		printf("Failed to initialize platform,"
		       "NULL pointer to store platform data.\n");
		return -EINVAL;
	}
	/* Initialize HW system components */
	init_system();

	if (argc >= 2) {
		proc_id = strtoul(argv[1], NULL, 0);
	}

	if (argc >= 3) {
		rsc_id = strtoul(argv[2], NULL, 0);
	}

	rproc = platform_create_proc(proc_id, rsc_id);
	if (!rproc) {
		printf("Failed to create remoteproc device.\n");
		return -EINVAL;
	}
	*platform = rproc;
	return 0;
}

struct  rpmsg_device *
platform_create_rpmsg_vdev(void *platform, unsigned int vdev_index,
			   unsigned int role,
			   void (*rst_cb)(struct virtio_device *vdev),
			   rpmsg_ns_bind_cb ns_bind_cb)
{
	struct remoteproc *rproc = platform;
	struct rpmsg_virtio_device *rpmsg_vdev;
	struct virtio_device *vdev;
	void *shbuf;
	struct metal_io_region *shbuf_io;
	int ret;

	/* Setup resource table */
	rpmsg_vdev = metal_allocate_memory(sizeof(*rpmsg_vdev));
	if (!rpmsg_vdev)
		return NULL;
	shbuf_io = remoteproc_get_io_with_pa(rproc, SHARED_BUF_PA);
	if (!shbuf_io)
		return NULL;
	shbuf = metal_io_phys_to_virt(shbuf_io, SHARED_BUF_PA);

	printf("creating remoteproc virtio -- test\r\n");
	/* TODO: can we have a wrapper for the following two functions? */
	vdev = remoteproc_create_virtio(rproc, vdev_index, role, rst_cb);
	if (!vdev) {
		printf("failed remoteproc_create_virtio\r\n");
		goto err1;
	}

	printf("initializing rpmsg shared buffer pool\r\n");
	/* Only RPMsg virtio master needs to initialize the shared buffers pool */
	rpmsg_virtio_init_shm_pool(&shpool, shbuf, SHARED_BUF_SIZE);

	printf("initializing rpmsg vdev\r\n");
	/* RPMsg virtio slave can set shared buffers pool argument to NULL */
	ret =  rpmsg_init_vdev(rpmsg_vdev, vdev, ns_bind_cb,
			       shbuf_io,
			       &shpool);
	if (ret) {
		printf("failed rpmsg_init_vdev\r\n");
		goto err2;
	}
	return rpmsg_virtio_get_rpmsg_device(rpmsg_vdev);
err2:
	remoteproc_remove_virtio(rproc, vdev);
err1:
	metal_free_memory(rpmsg_vdev);
	return NULL;
}

int platform_poll(void *priv)
{
	struct remoteproc *rproc = priv;

	remoteproc_get_notification(rproc, RSC_NOTIFY_ID_ANY);
	return 0;
}

void platform_release_rpmsg_vdev(struct rpmsg_device *rpdev)
{
	(void)rpdev;
}

void platform_cleanup(void *platform)
{
	struct remoteproc *rproc = platform;

	if (rproc)
		remoteproc_remove(rproc);
	cleanup_system();
}
