/*
 * Arm virt DRTM SMC dispatch internals
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_SMC_INTERNAL_H
#define HW_ARM_VIRT_DRTM_SMC_INTERNAL_H

#include "hw/arm/virt-drtm.h"
#include "system/tpm.h"
#include "virt-drtm-features-internal.h"

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

typedef struct VirtDRTMSMCResult {
    VirtDRTMResult status;
    bool has_x1;
    uint64_t x1;
    /* A successful handoff or remediation reset does not return to the PE. */
    bool non_returning;
    VirtDRTMLaunchStage launch_stage;
} VirtDRTMSMCResult;

typedef struct VirtDRTMSMCOps {
    bool (*ensure_ready)(void *opaque, Error **errp);
    bool (*guest_is_ram)(void *opaque, uint64_t address, uint64_t size);
    bool (*read_guest)(void *opaque, uint64_t address, void *data,
                       size_t size);
    bool (*close_locality)(void *opaque, uint8_t locality,
                           TPMDRTMLocalityCloseResult *result, Error **errp);
    void (*request_cold_reset)(void *opaque);
    VirtDRTMFeaturesResult (*features)(void *opaque, uint64_t query);
    VirtDRTMLaunchResult (*dynamic_launch)(void *opaque,
                                          uint64_t parameters_address,
                                          Error **errp);
} VirtDRTMSMCOps;

/*
 * Dependency-injected form of the service dispatch.  Only has_x1 results are
 * architected to update X1; all other calls leave the caller's X1 unchanged.
 */
VirtDRTMSMCResult virt_drtm_smc_dispatch_with_ops(
    VirtDRTMState *s, bool caller_aarch64, uint32_t function, uint64_t x1,
    const VirtDRTMSMCOps *ops, void *opaque, Error **errp);

#endif
