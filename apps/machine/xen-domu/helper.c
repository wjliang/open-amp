
/*
 * Copyright (c) 2014, Mentor Graphics Corporation
 * All rights reserved.
 *
 * Copyright (c) 2018 Xilinx, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <metal/sys.h>

int init_system()
{
	struct metal_init_params metal_param = METAL_INIT_DEFAULTS;

	metal_param.log_level = LOG_DEBUG;
	metal_init(&metal_param);

	return 0;
	return 0;
}

void cleanup_system()
{
	metal_finish();
}
