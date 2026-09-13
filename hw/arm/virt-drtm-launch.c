/*
 * Arm virt DRTM launch transaction
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/arm/virt-drtm-launch.h"

#define DRTM_ERROR_TCB_HASHES_NOT_LOCKED 0x04
#define DRTM_ERROR_TPM                   0x05
#define DRTM_ERROR_UNSPECIFIED           0xff

static VirtDRTMLaunchResult returnable(VirtDRTMResult result)
{
    return (VirtDRTMLaunchResult) {
        .result = result,
        .stage = VIRT_DRTM_LAUNCH_PROBE,
    };
}

static VirtDRTMLaunchResult remediate(VirtDRTMWorkflow *workflow,
                                      VirtDRTMLaunchStage stage,
                                      uint8_t error_id,
                                      const VirtDRTMLaunchOps *ops,
                                      void *opaque)
{
    virt_drtm_workflow_remediate(workflow, error_id);
    /* R47030 requires reset request to be the final remediation action. */
    ops->request_cold_reset(opaque);
    return (VirtDRTMLaunchResult) {
        .result = VIRT_DRTM_TPM_ERROR,
        .stage = stage,
        .committed = true,
        .reset_requested = true,
        .non_returning = true,
    };
}

VirtDRTMLaunchResult virt_drtm_launch_execute(
    VirtDRTMWorkflow *workflow, const VirtDRTMLaunchPlan *plan,
    bool mutable_tcb_ready, const VirtDRTMLaunchOps *ops, void *opaque,
    Error **errp)
{
    const VirtDRTMLaunchPlanInfo *info;
    const VirtDRTMMeasurementManifest *manifest;
    TPMDRTMLocalityCloseResult close_result;
    VirtDRTMTPMResult tpm_result;
    VirtDRTMResult result;
    bool no_active;

    g_assert(workflow);
    g_assert(plan);
    if (!ops || !ops->no_active_locality || !ops->open_localities ||
        !ops->hash_dce || !ops->extend_dcrtm || !ops->extend_dce ||
        !ops->write ||
        !ops->close_locality3 ||
        !ops->activate_locality2 || !ops->enter_dlme ||
        !ops->request_cold_reset) {
        error_setg(errp, "incomplete DRTM launch operations");
        return returnable(VIRT_DRTM_INTERNAL_ERROR);
    }

    if (!ops->no_active_locality(opaque, &no_active, errp)) {
        return returnable(VIRT_DRTM_TPM_ERROR);
    }
    if (!no_active) {
        return returnable(VIRT_DRTM_DENIED);
    }

    info = virt_drtm_launch_plan_info(plan);
    /* The manifest is owned by and sealed with the immutable plan. */
    manifest = virt_drtm_launch_plan_manifest(plan);
    result = virt_drtm_workflow_begin(workflow, plan);
    if (result != VIRT_DRTM_SUCCESS) {
        return returnable(result);
    }

    /*
     * Firmware-backed DRTM enters its non-returning phase before R44100.
     * Open the dynamic localities before the locality-4 R44090 hash sequence;
     * this follows the Table 25 lifecycle and makes locality 3 available for
     * the caps and extends that follow HASH_END.  Hardware-backed DRTM has a
     * different explicitly ordered sequence and is not modeled here.
     */
    if (!ops->open_localities(opaque, errp)) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_OPEN_LOCALITIES,
                         DRTM_ERROR_TPM, ops, opaque);
    }
    if (virt_drtm_workflow_open_localities(workflow) != VIRT_DRTM_SUCCESS) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_OPEN_LOCALITIES,
                         DRTM_ERROR_UNSPECIFIED, ops, opaque);
    }
    tpm_result = ops->hash_dce(opaque, manifest, errp);
    if (tpm_result.status != VIRT_DRTM_TPM_OK) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_HASH_DCE,
                         DRTM_ERROR_TPM, ops, opaque);
    }
    tpm_result = ops->extend_dcrtm(opaque, manifest, errp);
    if (tpm_result.status != VIRT_DRTM_TPM_OK) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_EXTEND_DCRTM,
                         DRTM_ERROR_TPM, ops, opaque);
    }
    if (virt_drtm_workflow_enter_dce(workflow) != VIRT_DRTM_SUCCESS) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_EXTEND_DCRTM,
                         DRTM_ERROR_UNSPECIFIED, ops, opaque);
    }
    tpm_result = ops->extend_dce(opaque, manifest, errp);
    if (tpm_result.status != VIRT_DRTM_TPM_OK) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_EXTEND_DCE,
                         DRTM_ERROR_TPM, ops, opaque);
    }

    /* R45290 is deliberately a post-D-CRTM DCE remediation failure. */
    if (!mutable_tcb_ready) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_TCB_LOCK,
                         DRTM_ERROR_TCB_HASHES_NOT_LOCKED, ops, opaque);
    }
    if (!ops->write(opaque, info->dlme_address + info->data_offset,
                    info->dlme_data, info->dlme_data_size, errp)) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_WRITE_DATA,
                         DRTM_ERROR_UNSPECIFIED, ops, opaque);
    }
    if (!ops->close_locality3(opaque, &close_result, errp) ||
        close_result != TPM_DRTM_LOCALITY_CLOSED) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3,
                         DRTM_ERROR_TPM, ops, opaque);
    }
    if (virt_drtm_workflow_relinquish_locality(workflow, 3) !=
            VIRT_DRTM_SUCCESS ||
        virt_drtm_workflow_close_locality(workflow, 3) !=
            VIRT_DRTM_SUCCESS) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3,
                         DRTM_ERROR_UNSPECIFIED, ops, opaque);
    }
    if (!ops->activate_locality2(opaque, errp)) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2,
                         DRTM_ERROR_TPM, ops, opaque);
    }
    if (virt_drtm_workflow_activate_locality2(workflow) !=
        VIRT_DRTM_SUCCESS) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2,
                         DRTM_ERROR_UNSPECIFIED, ops, opaque);
    }
    if (!ops->enter_dlme(opaque, info->dlme_address, info->data_offset,
                         info->entry_address, errp)) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_CPU_ENTRY,
                         DRTM_ERROR_UNSPECIFIED, ops, opaque);
    }
    if (virt_drtm_workflow_enter_dlme(workflow) != VIRT_DRTM_SUCCESS) {
        return remediate(workflow, VIRT_DRTM_LAUNCH_CPU_ENTRY,
                         DRTM_ERROR_UNSPECIFIED, ops, opaque);
    }

    return (VirtDRTMLaunchResult) {
        .result = VIRT_DRTM_SUCCESS,
        .stage = VIRT_DRTM_LAUNCH_COMPLETE,
        .committed = true,
        .non_returning = true,
    };
}
