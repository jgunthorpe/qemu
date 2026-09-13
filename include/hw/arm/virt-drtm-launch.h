/*
 * Arm virt DRTM launch transaction
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_LAUNCH_H
#define HW_ARM_VIRT_DRTM_LAUNCH_H

#include "hw/arm/virt-drtm-tpm.h"
#include "hw/arm/virt-drtm-workflow.h"

typedef enum VirtDRTMLaunchStage {
    VIRT_DRTM_LAUNCH_PROBE,
    VIRT_DRTM_LAUNCH_OPEN_LOCALITIES,
    VIRT_DRTM_LAUNCH_HASH_DCE,
    VIRT_DRTM_LAUNCH_EXTEND_DCRTM,
    VIRT_DRTM_LAUNCH_EXTEND_DCE,
    VIRT_DRTM_LAUNCH_TCB_LOCK,
    VIRT_DRTM_LAUNCH_WRITE_DATA,
    VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3,
    VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2,
    VIRT_DRTM_LAUNCH_CPU_ENTRY,
    VIRT_DRTM_LAUNCH_COMPLETE,
} VirtDRTMLaunchStage;

typedef struct VirtDRTMLaunchResult {
    VirtDRTMResult result;
    VirtDRTMLaunchStage stage;
    bool committed;
    /* Diagnostics for a harness; non_returning results are not SMC returns. */
    bool reset_requested;
    bool non_returning;
} VirtDRTMLaunchResult;

typedef struct VirtDRTMLaunchOps {
    bool (*no_active_locality)(void *opaque, bool *no_active, Error **errp);
    bool (*open_localities)(void *opaque, Error **errp);
    VirtDRTMTPMResult (*hash_dce)(void *opaque,
        const VirtDRTMMeasurementManifest *manifest, Error **errp);
    VirtDRTMTPMResult (*extend_dcrtm)(void *opaque,
        const VirtDRTMMeasurementManifest *manifest, Error **errp);
    VirtDRTMTPMResult (*extend_dce)(void *opaque,
        const VirtDRTMMeasurementManifest *manifest, Error **errp);
    bool (*write)(void *opaque, uint64_t address, const uint8_t *data,
                  size_t size, Error **errp);
    bool (*close_locality3)(void *opaque,
                           TPMDRTMLocalityCloseResult *result, Error **errp);
    bool (*activate_locality2)(void *opaque, Error **errp);
    bool (*enter_dlme)(void *opaque, uint64_t dlme_address,
                       uint64_t data_offset, uint64_t entry_address,
                       Error **errp);
    void (*request_cold_reset)(void *opaque);
} VirtDRTMLaunchOps;

/*
 * Commit an already snapshotted launch plan.  A failure of the initial TPM
 * probe is returnable and leaves both workflow and guest state unchanged.
 * Once workflow_begin succeeds, every failure records its actual firmware
 * D-CRTM/DCE phase and requests a cold reset.  Such a result is an internal
 * diagnostic for the harness and must not reach the original caller.
 *
 * write() must implement an all-or-fail checked guest write.  The caller
 * holds the BQL, and all callbacks are synchronous.
 * mutable_tcb_ready is true when no mutable hashes were supplied or when
 * the nonempty set was locked as required by R45290.
 */
VirtDRTMLaunchResult virt_drtm_launch_execute(
    VirtDRTMWorkflow *workflow, const VirtDRTMLaunchPlan *plan,
    bool mutable_tcb_ready, const VirtDRTMLaunchOps *ops, void *opaque,
    Error **errp);

#endif
