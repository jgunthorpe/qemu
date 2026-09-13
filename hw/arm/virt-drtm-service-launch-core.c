/*
 * Arm virt DRTM service launch assembly
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"
#include "hw/arm/virt-drtm.h"
#include "hw/arm/virt-drtm-service-launch-internal.h"
#include "virt-drtm-features-internal.h"

#ifdef CONFIG_TPM
static VirtDRTMLaunchResult launch_returnable(VirtDRTMResult result)
{
    return (VirtDRTMLaunchResult) {
        .result = result,
        .stage = VIRT_DRTM_LAUNCH_PROBE,
    };
}

VirtDRTMLaunchResult virt_drtm_service_launch_with_ops(
    VirtDRTMState *s, uint64_t parameters_address, bool caller_aarch64,
    bool caller_is_boot_pe, bool secondary_off,
    size_t address_map_capacity,
    const VirtDRTMServiceLaunchOps *ops, void *opaque, Error **errp)
{
    VirtDRTMCapabilities capabilities;
    uint32_t supported_features;
    const VirtDRTMParameters *parameters = NULL;
    g_autofree uint8_t *dlme_image = NULL;
    g_autofree uint8_t *dce_image = NULL;
    g_autofree VirtDRTMMemoryRegion *protected = NULL;
    g_autofree VirtDRTMTCBHash *hashes = NULL;
    g_autofree VirtDRTMMemoryRegion *address_map = NULL;
    size_t address_map_count = 0;
    VirtDRTMLaunchPlan *plan = NULL;
    VirtDRTMTCBStatus mutable_status;
    VirtDRTMPreflightInput preflight;
    VirtDRTMEventLogInput event;
    VirtDRTMDataInput data;
    VirtDRTMParamStatus parameter_status;
    VirtDRTMResult result;
    VirtDRTMLaunchResult launch_result;
    size_t hash_count;
    bool mutable_ready, no_active;

    g_assert(bql_locked());
    g_assert(s);
    g_assert(ops);
    if (!virt_drtm_features_launch_capabilities(
            s, address_map_capacity, &capabilities, &supported_features)) {
        return launch_returnable(VIRT_DRTM_INTERNAL_ERROR);
    }
    if (!ops->read || !ops->is_ram || !ops->alloc ||
        !ops->snapshot_address_map || !ops->prepare_tpm) {
        return launch_returnable(VIRT_DRTM_INTERNAL_ERROR);
    }
    if (!s->enabled || !s->tpm_ready) {
        return launch_returnable(VIRT_DRTM_NOT_SUPPORTED);
    }
    if (!caller_aarch64 || !caller_is_boot_pe) {
        return launch_returnable(VIRT_DRTM_DENIED);
    }
    if (!secondary_off) {
        return launch_returnable(VIRT_DRTM_SECONDARY_PE_NOT_OFF);
    }
    if (!ops->launch.no_active_locality ||
        !ops->launch.no_active_locality(opaque, &no_active, errp)) {
        return launch_returnable(VIRT_DRTM_TPM_ERROR);
    }
    if (!no_active) {
        return launch_returnable(VIRT_DRTM_DENIED);
    }
    /*
     * The DLME may have relinquished locality 2 directly through TPM MMIO.
     * Reflect that prior guest action only after the TPM has authoritatively
     * reported that no locality is active.  This is intentionally before
     * parameter validation: a later returnable failure did not cause the
     * relinquishment and must not make the workflow stale again.
     */
    virt_drtm_workflow_observe_no_active_locality(&s->workflow);

    /*
     * D-CRTM phase 1 is still returnable while the system is unchanged.
     * Snapshot and seal every guest-controlled input into private storage so
     * phase 2 and the DCE cannot observe a post-validation mutation.  This
     * does not populate guest DLME data; the transaction performs that DCE
     * effect after workflow_begin(), where any write failure remediates.
     */
    parameter_status = virt_drtm_params_decode(
        parameters_address, &capabilities, ops->read, ops->is_ram, opaque,
        &parameters);
    if (parameter_status != VIRT_DRTM_PARAM_SUCCESS) {
        return launch_returnable((VirtDRTMResult)parameter_status);
    }
    if ((uint64_t)(size_t)parameters->image_size != parameters->image_size ||
        (parameters->has_dce &&
         (uint64_t)(size_t)parameters->dce_size != parameters->dce_size)) {
        launch_result = launch_returnable(VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
        goto out;
    }
    dlme_image = ops->alloc(parameters->image_size);
    if (!dlme_image) {
        launch_result =
            launch_returnable(VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
        goto out;
    }
    if (!ops->read(opaque, parameters->image_address,
                   dlme_image, parameters->image_size)) {
        launch_result = launch_returnable(VIRT_DRTM_INVALID_DATA);
        goto out;
    }
    if (parameters->has_dce) {
        dce_image = ops->alloc(parameters->dce_size);
        if (!dce_image) {
            launch_result =
                launch_returnable(VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
            goto out;
        }
        if (!ops->read(opaque, parameters->dce_address,
                       dce_image, parameters->dce_size)) {
            launch_result = launch_returnable(VIRT_DRTM_INVALID_DATA);
            goto out;
        }
    }

    hash_count = s->tcb_hashes.count;
    if (hash_count) {
        hashes = ops->alloc(hash_count * sizeof(*hashes));
        if (!hashes) {
            launch_result =
                launch_returnable(VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
            goto out;
        }
    }
    mutable_status = virt_drtm_tcb_snapshot(
        &s->tcb_hashes, hashes, hash_count, &mutable_ready);
    if (mutable_status != VIRT_DRTM_TCB_SUCCESS) {
        launch_result = launch_returnable(VIRT_DRTM_INTERNAL_ERROR);
        goto out;
    }
    result = ops->snapshot_address_map(opaque, &address_map,
                                       &address_map_count);
    if (result != VIRT_DRTM_SUCCESS) {
        launch_result = launch_returnable(result);
        goto out;
    }
    if (address_map_count > address_map_capacity) {
        launch_result =
            launch_returnable(VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
        goto out;
    }
    if (parameters->protected_region_count) {
        protected = ops->alloc(parameters->protected_region_count *
                               sizeof(*protected));
        if (!protected) {
            launch_result =
                launch_returnable(VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
            goto out;
        }
        for (uint32_t i = 0; i < parameters->protected_region_count; i++) {
            protected[i] = (VirtDRTMMemoryRegion) {
                .address = parameters->protected_regions[i].address,
                .size = parameters->protected_regions[i].size,
                .type = VIRT_DRTM_MEMORY_NORMAL,
            };
        }
    }

    event = (VirtDRTMEventLogInput) {
        .active_banks = s->active_banks,
        .active_bank_count = s->active_bank_count,
        .pcr_schema_value = BIT(parameters->pcr_schema),
        .dce_image = { dce_image, parameters->dce_size },
        .secure_interrupts_disabled = parameters->disable_secure_interrupts,
        .debug_or_trace_enabled = ops->debug_or_trace_enabled,
        .nonsecure_lifecycle = ops->nonsecure_lifecycle,
        .dlme_image = { dlme_image, parameters->image_size },
        .dlme_entry_point_offset = parameters->entry_address -
                                   parameters->image_address,
    };
    data = (VirtDRTMDataInput) {
        .dlme_address = parameters->dlme_address,
        .dlme_size = parameters->dlme_size,
        .image_address = parameters->image_address,
        .image_size = parameters->image_size,
        .complete_protection = parameters->memory_protection == 0,
        .protected_regions = protected,
        .protected_region_count = parameters->protected_region_count,
        .address_map = address_map,
        .address_map_count = address_map_count,
        .firmware_hash_algorithm = s->firmware_hash_algorithm,
        .tcb_hashes = hashes,
        .tcb_hash_count = hash_count,
    };
    preflight = (VirtDRTMPreflightInput) {
        .caller_aarch64 = true,
        .caller_is_boot_pe = true,
        .secondary_pes_off = true,
        .no_active_tpm_locality = true,
        .supported_launch_features = supported_features,
        .parameter_status = parameter_status,
        .parameters = parameters,
        .event_log = &event,
        .data = &data,
    };
    result = virt_drtm_workflow_preflight(&s->workflow, &preflight, &plan);
    if (result != VIRT_DRTM_SUCCESS) {
        launch_result = launch_returnable(result);
        goto out;
    }
    if (!ops->prepare_tpm(opaque, virt_drtm_launch_plan_manifest(plan),
                          errp)) {
        launch_result = launch_returnable(VIRT_DRTM_TPM_ERROR);
        goto out;
    }
    launch_result = virt_drtm_launch_execute(
        &s->workflow, plan, mutable_ready, &ops->launch, opaque, errp);

out:
    virt_drtm_launch_plan_free(plan);
    virt_drtm_params_free(parameters);
    return launch_result;
}

#endif
