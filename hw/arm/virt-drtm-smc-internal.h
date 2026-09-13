/*
 * Arm virt DRTM SMC dispatch internals
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_SMC_INTERNAL_H
#define HW_ARM_VIRT_DRTM_SMC_INTERNAL_H

#define DRTM_FID_BASE                  0xc4000110U
#define DRTM_VERSION                   (DRTM_FID_BASE + 0)
#define DRTM_FEATURES                  (DRTM_FID_BASE + 1)
#define DRTM_UNPROTECT_MEMORY          (DRTM_FID_BASE + 3)
#define DRTM_DYNAMIC_LAUNCH            (DRTM_FID_BASE + 4)
#define DRTM_CLOSE_LOCALITY            (DRTM_FID_BASE + 5)
#define DRTM_GET_ERROR                 (DRTM_FID_BASE + 6)
#define DRTM_SET_ERROR                 (DRTM_FID_BASE + 7)
#define DRTM_SET_TCB_HASH              (DRTM_FID_BASE + 8)
#define DRTM_LOCK_TCB_HASHES           (DRTM_FID_BASE + 9)
#define DRTM_ENABLE_SECURE_INTERRUPTS  (DRTM_FID_BASE + 10)

#endif
