/*
 * Arm virt DRTM workflow model
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "hw/arm/virt-drtm-workflow.h"

struct VirtDRTMLaunchPlan {
    VirtDRTMLaunchPlanInfo info;
    VirtDRTMMeasurementManifest *manifest;
    uint64_t seal;
    uint8_t payload[];
};

#define VIRT_DRTM_PLAN_SEAL UINT64_C(0x4452544d504c414e)

static bool workflow_repeat_ready(const VirtDRTMWorkflow *workflow)
{
    return (workflow->phase == VIRT_DRTM_PHASE_READY &&
            workflow->locality[1] == VIRT_DRTM_LOCALITY_CLOSED &&
            workflow->locality[2] == VIRT_DRTM_LOCALITY_CLOSED &&
            workflow->locality[3] == VIRT_DRTM_LOCALITY_CLOSED &&
            !workflow->protection_release_available &&
            workflow->protection == VIRT_DRTM_PROTECTION_NONE) ||
        (workflow->phase == VIRT_DRTM_PHASE_DLME &&
         !workflow->protection_release_available &&
         (workflow->locality[2] == VIRT_DRTM_LOCALITY_RELINQUISHED ||
          workflow->locality[2] == VIRT_DRTM_LOCALITY_CLOSED) &&
         workflow->locality[3] == VIRT_DRTM_LOCALITY_CLOSED &&
         workflow->secure_interrupts != VIRT_DRTM_SECURE_INTERRUPTS_DISABLED);
}

void virt_drtm_workflow_init(VirtDRTMWorkflow *workflow)
{
    memset(workflow, 0, sizeof(*workflow));
    workflow->phase = VIRT_DRTM_PHASE_READY;
    workflow->locality[1] = VIRT_DRTM_LOCALITY_CLOSED;
    workflow->locality[2] = VIRT_DRTM_LOCALITY_CLOSED;
    workflow->locality[3] = VIRT_DRTM_LOCALITY_CLOSED;
}

void virt_drtm_workflow_reset(VirtDRTMWorkflow *workflow)
{
    uint64_t sticky_error = workflow->sticky_error;
    uint64_t launch_sequence = workflow->launch_sequence;

    virt_drtm_workflow_init(workflow);
    workflow->sticky_error = sticky_error;
    /* Invalidate any pre-reset transaction plan. */
    workflow->launch_sequence = launch_sequence + 1;
}

void virt_drtm_workflow_observe_no_active_locality(
    VirtDRTMWorkflow *workflow)
{
    g_assert(workflow);

    /*
     * R43010 permits a later launch after the DLME relinquishes locality 2.
     * TPM MMIO has no service-call edge on which to update the workflow, so
     * accept a successful no-active-locality observation as evidence of that
     * already-completed guest action.  Keep the transition narrow: an active
     * locality in any other phase, or alongside an incomplete locality 3
     * lifecycle, remains an inconsistent state and must still be denied.
     */
    if (workflow->phase == VIRT_DRTM_PHASE_DLME &&
        workflow->locality[1] == VIRT_DRTM_LOCALITY_OPEN &&
        workflow->locality[2] == VIRT_DRTM_LOCALITY_ACTIVE &&
        workflow->locality[3] == VIRT_DRTM_LOCALITY_CLOSED) {
        workflow->locality[2] = VIRT_DRTM_LOCALITY_RELINQUISHED;
    }
}

static VirtDRTMResult parameter_result(VirtDRTMParamStatus status)
{
    switch (status) {
    case VIRT_DRTM_PARAM_SUCCESS:
        return VIRT_DRTM_SUCCESS;
    case VIRT_DRTM_INVALID_PARAMETERS:
        return VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS;
    case VIRT_DRTM_MEM_PROTECT_INVALID:
        return VIRT_DRTM_WORKFLOW_MEM_PROTECT_INVALID;
    case VIRT_DRTM_OUT_OF_RESOURCE:
        return VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE;
    default:
        return VIRT_DRTM_INTERNAL_ERROR;
    }
}

static bool inputs_agree(const VirtDRTMParameters *parameters,
                         const VirtDRTMEventLogInput *event,
                         const VirtDRTMDataInput *data)
{
    uint32_t features = parameters->launch_features;
    uint64_t entry_offset = parameters->entry_address -
                            parameters->image_address;
    uint16_t firmware_hash_algorithm;

    if (virt_drtm_firmware_hash_select(event->active_banks,
                                       event->active_bank_count,
                                       &firmware_hash_algorithm) !=
        VIRT_DRTM_EVENT_LOG_OK) {
        return false;
    }

    return parameters->memory_protection == ((features >> 3) & 7) &&
        parameters->pcr_schema == ((features >> 1) & 3) &&
        parameters->tpm_hashing == !!(features & BIT(0)) &&
        parameters->image_authentication == !!(features & BIT(6)) &&
        parameters->disable_secure_interrupts == !!(features & BIT(7)) &&
        data->dlme_address == parameters->dlme_address &&
        data->dlme_size == parameters->dlme_size &&
        data->image_address == parameters->image_address &&
        data->image_size == parameters->image_size &&
        data->complete_protection == (parameters->memory_protection == 0) &&
        firmware_hash_algorithm == data->firmware_hash_algorithm &&
        event->pcr_schema_value == BIT(parameters->pcr_schema) &&
        event->dlme_image.size == parameters->image_size &&
        event->dlme_entry_point_offset == entry_offset &&
        event->secure_interrupts_disabled ==
            parameters->disable_secure_interrupts &&
        event->dce_image.size == parameters->dce_size;
}

VirtDRTMResult virt_drtm_workflow_preflight(
    const VirtDRTMWorkflow *workflow, const VirtDRTMPreflightInput *input,
    VirtDRTMLaunchPlan **result)
{
    VirtDRTMEventLogStatus event_status;
    VirtDRTMDataStatus data_status;
    VirtDRTMDataInput data;
    VirtDRTMLaunchPlan *plan, *resized;
    VirtDRTMResult status;
    VirtDRTMMeasurementManifest *manifest = NULL;
    size_t event_size, data_size, allocation_size;

    g_assert(workflow);
    g_assert(input);
    g_assert(result);
    *result = NULL;
    if (!workflow_repeat_ready(workflow)) {
        return VIRT_DRTM_DENIED;
    }
    if (!input->caller_aarch64 || !input->caller_is_boot_pe) {
        return VIRT_DRTM_DENIED;
    }
    if (!input->secondary_pes_off) {
        return VIRT_DRTM_SECONDARY_PE_NOT_OFF;
    }
    if (!input->no_active_tpm_locality) {
        return VIRT_DRTM_DENIED;
    }
    status = parameter_result(input->parameter_status);
    if (status != VIRT_DRTM_SUCCESS) {
        return status;
    }
    if (!input->parameters || !input->event_log || !input->data ||
        (input->parameters->launch_features &
         ~input->supported_launch_features) ||
        !inputs_agree(input->parameters, input->event_log, input->data)) {
        return VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS;
    }

    event_status = virt_drtm_measurement_manifest_build(input->event_log,
                                                         &manifest);
    if (event_status != VIRT_DRTM_EVENT_LOG_OK) {
        return event_status == VIRT_DRTM_EVENT_LOG_OVERFLOW ?
            VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE : VIRT_DRTM_INVALID_DATA;
    }

    event_status = virt_drtm_event_log_build(input->event_log, NULL, 0,
                                              &event_size);
    if (event_status != VIRT_DRTM_EVENT_LOG_OK) {
        virt_drtm_measurement_manifest_free(manifest);
        return event_status == VIRT_DRTM_EVENT_LOG_OVERFLOW ?
            VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE : VIRT_DRTM_INVALID_DATA;
    }
    if (event_size > SIZE_MAX - sizeof(*plan)) {
        virt_drtm_measurement_manifest_free(manifest);
        return VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE;
    }
    plan = g_try_malloc(sizeof(*plan) + event_size);
    if (!plan) {
        virt_drtm_measurement_manifest_free(manifest);
        return VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE;
    }
    event_status = virt_drtm_event_log_build(input->event_log, plan->payload,
                                              event_size, &event_size);
    if (event_status != VIRT_DRTM_EVENT_LOG_OK) {
        virt_drtm_measurement_manifest_free(manifest);
        g_free(plan);
        return VIRT_DRTM_INTERNAL_ERROR;
    }

    data = *input->data;
    data.event_log = (VirtDRTMBlob) { plan->payload, event_size };
    data_status = virt_drtm_data_build(&data, input->parameters->data_address,
                                       NULL, 0, &data_size);
    if (data_status != VIRT_DRTM_DATA_OK) {
        virt_drtm_measurement_manifest_free(manifest);
        g_free(plan);
        return data_status == VIRT_DRTM_DATA_OVERFLOW ?
            VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE : VIRT_DRTM_INVALID_DATA;
    }
    if (data_size > SIZE_MAX - sizeof(*plan) - event_size) {
        virt_drtm_measurement_manifest_free(manifest);
        g_free(plan);
        return VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE;
    }
    allocation_size = sizeof(*plan) + event_size + data_size;
    resized = g_try_realloc(plan, allocation_size);
    if (!resized) {
        virt_drtm_measurement_manifest_free(manifest);
        g_free(plan);
        return VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE;
    }
    plan = resized;
    data.event_log.data = plan->payload;
    data_status = virt_drtm_data_build(&data, input->parameters->data_address,
                                       plan->payload + event_size, data_size,
                                       &data_size);
    if (data_status != VIRT_DRTM_DATA_OK) {
        virt_drtm_measurement_manifest_free(manifest);
        g_free(plan);
        return VIRT_DRTM_INTERNAL_ERROR;
    }

    plan->info = (VirtDRTMLaunchPlanInfo) {
        .expected_launch_sequence = workflow->launch_sequence,
        .effects = VIRT_DRTM_EFFECT_OPEN_LOCALITIES |
                   VIRT_DRTM_EFFECT_BUILD_SOFTWARE_MEASUREMENTS |
                   VIRT_DRTM_EFFECT_PROTECT_MEMORY |
                   VIRT_DRTM_EFFECT_WRITE_DLME_DATA |
                   VIRT_DRTM_EFFECT_CLOSE_LOCALITY_3 |
                   VIRT_DRTM_EFFECT_ACTIVATE_LOCALITY_2 |
                   VIRT_DRTM_EFFECT_CLEAR_ERROR |
                   VIRT_DRTM_EFFECT_ENTER_DLME |
                   (input->parameters->disable_secure_interrupts ?
                    VIRT_DRTM_EFFECT_DISABLE_SECURE_INTERRUPTS : 0),
        .dlme_address = input->parameters->dlme_address,
        .data_offset = input->parameters->data_offset,
        .entry_address = input->parameters->entry_address,
        .memory_protection = input->parameters->memory_protection,
        .disable_secure_interrupts =
            input->parameters->disable_secure_interrupts,
        .event_log = plan->payload,
        .event_log_size = event_size,
        .dlme_data = plan->payload + event_size,
        .dlme_data_size = data_size,
    };
    plan->manifest = manifest;
    plan->seal = VIRT_DRTM_PLAN_SEAL;
    *result = plan;
    return VIRT_DRTM_SUCCESS;
}

void virt_drtm_launch_plan_free(VirtDRTMLaunchPlan *plan)
{
    if (plan) {
        virt_drtm_measurement_manifest_free(plan->manifest);
    }
    g_free(plan);
}

const VirtDRTMLaunchPlanInfo *virt_drtm_launch_plan_info(
    const VirtDRTMLaunchPlan *plan)
{
    g_assert(plan);
    g_assert(plan->seal == VIRT_DRTM_PLAN_SEAL);
    return &plan->info;
}

const VirtDRTMMeasurementManifest *virt_drtm_launch_plan_manifest(
    const VirtDRTMLaunchPlan *plan)
{
    g_assert(plan);
    g_assert(plan->seal == VIRT_DRTM_PLAN_SEAL);
    return plan->manifest;
}

VirtDRTMResult virt_drtm_workflow_begin(VirtDRTMWorkflow *workflow,
                                        const VirtDRTMLaunchPlan *plan)
{
    const VirtDRTMLaunchPlanInfo *info;

    g_assert(workflow);
    g_assert(plan);
    if (plan->seal != VIRT_DRTM_PLAN_SEAL) {
        return VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS;
    }
    info = &plan->info;
    if (!workflow_repeat_ready(workflow) ||
        info->expected_launch_sequence != workflow->launch_sequence ||
        info->memory_protection > 1) {
        return VIRT_DRTM_DENIED;
    }

    workflow->phase = VIRT_DRTM_PHASE_DCRTM;
    workflow->protection = info->memory_protection ?
        VIRT_DRTM_PROTECTION_REGION : VIRT_DRTM_PROTECTION_COMPLETE;
    workflow->protection_release_available = true;
    workflow->secure_interrupts = info->disable_secure_interrupts ?
        VIRT_DRTM_SECURE_INTERRUPTS_DISABLED :
        VIRT_DRTM_SECURE_INTERRUPTS_NOT_REQUESTED;
    workflow->error_set_this_launch = false;
    workflow->launch_sequence++;
    return VIRT_DRTM_SUCCESS;
}

VirtDRTMResult virt_drtm_workflow_open_localities(VirtDRTMWorkflow *workflow)
{
    g_assert(workflow);
    /*
     * R43010 permits a launch without an intervening reset.  Locality 1 has
     * no architected close operation, so R44100 reopening it is idempotent.
     * Locality 2 may be relinquished without being closed, because closing it
     * is optional for the DLME; locality 3 must have completed its mandatory
     * close lifecycle.
     */
    if (workflow->phase != VIRT_DRTM_PHASE_DCRTM ||
        (workflow->locality[1] != VIRT_DRTM_LOCALITY_CLOSED &&
         workflow->locality[1] != VIRT_DRTM_LOCALITY_OPEN) ||
        (workflow->locality[2] != VIRT_DRTM_LOCALITY_RELINQUISHED &&
         workflow->locality[2] != VIRT_DRTM_LOCALITY_CLOSED) ||
        workflow->locality[3] != VIRT_DRTM_LOCALITY_CLOSED) {
        return VIRT_DRTM_DENIED;
    }
    workflow->locality[1] = VIRT_DRTM_LOCALITY_OPEN;
    workflow->locality[2] = VIRT_DRTM_LOCALITY_OPEN;
    workflow->locality[3] = VIRT_DRTM_LOCALITY_ACTIVE;
    return VIRT_DRTM_SUCCESS;
}

VirtDRTMResult virt_drtm_workflow_enter_dce(VirtDRTMWorkflow *workflow)
{
    g_assert(workflow);
    if (workflow->phase != VIRT_DRTM_PHASE_DCRTM ||
        workflow->locality[1] != VIRT_DRTM_LOCALITY_OPEN ||
        workflow->locality[2] != VIRT_DRTM_LOCALITY_OPEN ||
        workflow->locality[3] != VIRT_DRTM_LOCALITY_ACTIVE) {
        return VIRT_DRTM_DENIED;
    }
    workflow->phase = VIRT_DRTM_PHASE_DCE;
    return VIRT_DRTM_SUCCESS;
}

VirtDRTMResult virt_drtm_workflow_enter_dlme(VirtDRTMWorkflow *workflow)
{
    g_assert(workflow);
    if (workflow->phase != VIRT_DRTM_PHASE_DCE ||
        workflow->locality[3] != VIRT_DRTM_LOCALITY_CLOSED ||
        workflow->locality[2] != VIRT_DRTM_LOCALITY_ACTIVE) {
        return VIRT_DRTM_DENIED;
    }
    workflow->phase = VIRT_DRTM_PHASE_DLME;
    return VIRT_DRTM_SUCCESS;
}

VirtDRTMResult virt_drtm_workflow_activate_locality2(
    VirtDRTMWorkflow *workflow)
{
    g_assert(workflow);
    if (workflow->phase != VIRT_DRTM_PHASE_DCE ||
        workflow->locality[3] != VIRT_DRTM_LOCALITY_CLOSED ||
        workflow->locality[2] != VIRT_DRTM_LOCALITY_OPEN) {
        return VIRT_DRTM_DENIED;
    }
    workflow->locality[2] = VIRT_DRTM_LOCALITY_ACTIVE;
    /* R45350: clear the persistent error before transferring control. */
    workflow->sticky_error = 0;
    return VIRT_DRTM_SUCCESS;
}

VirtDRTMResult virt_drtm_workflow_relinquish_locality(
    VirtDRTMWorkflow *workflow, unsigned int locality)
{
    g_assert(workflow);
    if (locality != 2 && locality != 3) {
        return VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS;
    }
    if ((locality == 2 && workflow->phase != VIRT_DRTM_PHASE_DLME) ||
        (locality == 3 && workflow->phase != VIRT_DRTM_PHASE_DCE)) {
        return VIRT_DRTM_DENIED;
    }
    if (workflow->locality[locality] == VIRT_DRTM_LOCALITY_CLOSED) {
        return VIRT_DRTM_ALREADY_CLOSED;
    }
    if (workflow->locality[locality] == VIRT_DRTM_LOCALITY_RELINQUISHED) {
        return VIRT_DRTM_DENIED;
    }
    workflow->locality[locality] = VIRT_DRTM_LOCALITY_RELINQUISHED;
    return VIRT_DRTM_SUCCESS;
}

VirtDRTMResult virt_drtm_workflow_close_locality(
    VirtDRTMWorkflow *workflow, unsigned int locality)
{
    g_assert(workflow);
    if (locality != 2 && locality != 3) {
        return VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS;
    }
    if (workflow->locality[locality] == VIRT_DRTM_LOCALITY_CLOSED) {
        return VIRT_DRTM_ALREADY_CLOSED;
    }
    if ((locality == 2 && workflow->phase != VIRT_DRTM_PHASE_DLME) ||
        (locality == 3 && workflow->phase != VIRT_DRTM_PHASE_DCE)) {
        return VIRT_DRTM_DENIED;
    }
    if (workflow->locality[locality] != VIRT_DRTM_LOCALITY_RELINQUISHED) {
        return VIRT_DRTM_DENIED;
    }
    workflow->locality[locality] = VIRT_DRTM_LOCALITY_CLOSED;
    return VIRT_DRTM_SUCCESS;
}

VirtDRTMResult virt_drtm_workflow_unprotect(VirtDRTMWorkflow *workflow)
{
    g_assert(workflow);
    if (workflow->phase != VIRT_DRTM_PHASE_DLME ||
        !workflow->protection_release_available) {
        return VIRT_DRTM_DENIED;
    }
    workflow->protection_release_available = false;
    workflow->protection = workflow->protection ==
        VIRT_DRTM_PROTECTION_COMPLETE ?
        VIRT_DRTM_PROTECTION_COMPLETE_RETAINED : VIRT_DRTM_PROTECTION_NONE;
    return VIRT_DRTM_SUCCESS;
}

VirtDRTMResult virt_drtm_workflow_enable_secure_interrupts(
    VirtDRTMWorkflow *workflow)
{
    g_assert(workflow);
    if (workflow->phase != VIRT_DRTM_PHASE_DLME ||
        workflow->secure_interrupts !=
        VIRT_DRTM_SECURE_INTERRUPTS_DISABLED) {
        return VIRT_DRTM_DENIED;
    }
    workflow->secure_interrupts = VIRT_DRTM_SECURE_INTERRUPTS_REENABLED;
    return VIRT_DRTM_SUCCESS;
}

uint64_t virt_drtm_workflow_get_error(const VirtDRTMWorkflow *workflow)
{
    g_assert(workflow);
    return workflow->sticky_error;
}

VirtDRTMResult virt_drtm_workflow_set_error(VirtDRTMWorkflow *workflow,
                                            uint64_t error)
{
    uint64_t error_id;
    uint64_t phase;

    g_assert(workflow);
    if ((workflow->phase != VIRT_DRTM_PHASE_DCE &&
         workflow->phase != VIRT_DRTM_PHASE_DLME) ||
        workflow->error_set_this_launch) {
        return VIRT_DRTM_DENIED;
    }
    /* SET_ERROR is exposed to a Normal-world DCE, whose phase encoding is 4. */
    phase = workflow->phase == VIRT_DRTM_PHASE_DLME ? 5 : 4;
    error_id = extract64(error, 3, 8);
    if (workflow->phase == VIRT_DRTM_PHASE_DLME || error_id == 0 ||
        error_id == 1 || (error_id >= 8 && error_id < 0xff)) {
        error_id = 0xff;
    }
    workflow->sticky_error = (error & ~MAKE_64BIT_MASK(0, 11)) |
                             (error_id << 3) | phase;
    workflow->error_set_this_launch = true;
    if (workflow->phase == VIRT_DRTM_PHASE_DCE) {
        workflow->phase = VIRT_DRTM_PHASE_REMEDIATION;
    }
    return VIRT_DRTM_SUCCESS;
}

void virt_drtm_workflow_remediate(VirtDRTMWorkflow *workflow,
                                  uint8_t error_id)
{
    uint64_t phase;

    g_assert(workflow);
    g_assert(workflow->phase != VIRT_DRTM_PHASE_READY);
    switch (workflow->phase) {
    case VIRT_DRTM_PHASE_DCRTM:
        phase = 1;
        break;
    case VIRT_DRTM_PHASE_DCE:
        phase = 3;
        break;
    case VIRT_DRTM_PHASE_DLME:
        phase = 5;
        break;
    default:
        g_assert_not_reached();
    }
    workflow->sticky_error = ((uint64_t)error_id << 3) | phase;
    workflow->error_set_this_launch = true;
    workflow->phase = VIRT_DRTM_PHASE_REMEDIATION;
}
