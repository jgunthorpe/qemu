/*
 * Arm virt DRTM workflow model
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_WORKFLOW_H
#define HW_ARM_VIRT_DRTM_WORKFLOW_H

#include "hw/arm/virt-drtm-data.h"
#include "hw/arm/virt-drtm-event-log.h"
#include "hw/arm/virt-drtm-measurement.h"
#include "hw/arm/virt-drtm-params.h"

typedef enum VirtDRTMResult {
    VIRT_DRTM_SUCCESS = 0,
    VIRT_DRTM_NOT_SUPPORTED = -1,
    VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS = -2,
    VIRT_DRTM_DENIED = -3,
    VIRT_DRTM_NOT_FOUND = -4,
    VIRT_DRTM_INTERNAL_ERROR = -5,
    VIRT_DRTM_WORKFLOW_MEM_PROTECT_INVALID = -6,
    VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE = -8,
    VIRT_DRTM_INVALID_DATA = -9,
    VIRT_DRTM_SECONDARY_PE_NOT_OFF = -10,
    VIRT_DRTM_ALREADY_CLOSED = -11,
    VIRT_DRTM_TPM_ERROR = -12,
} VirtDRTMResult;

typedef enum VirtDRTMPhase {
    VIRT_DRTM_PHASE_READY,
    VIRT_DRTM_PHASE_DCRTM,
    VIRT_DRTM_PHASE_DCE,
    VIRT_DRTM_PHASE_DLME,
    VIRT_DRTM_PHASE_REMEDIATION,
} VirtDRTMPhase;

typedef enum VirtDRTMLocalityState {
    VIRT_DRTM_LOCALITY_CLOSED,
    VIRT_DRTM_LOCALITY_OPEN,
    VIRT_DRTM_LOCALITY_ACTIVE,
    VIRT_DRTM_LOCALITY_RELINQUISHED,
} VirtDRTMLocalityState;

typedef enum VirtDRTMProtectionState {
    VIRT_DRTM_PROTECTION_NONE,
    VIRT_DRTM_PROTECTION_REGION,
    VIRT_DRTM_PROTECTION_COMPLETE,
    /* §3.5: complete mode succeeds without changing SMMU configuration. */
    VIRT_DRTM_PROTECTION_COMPLETE_RETAINED,
} VirtDRTMProtectionState;

typedef enum VirtDRTMSecureInterruptState {
    VIRT_DRTM_SECURE_INTERRUPTS_NOT_REQUESTED,
    VIRT_DRTM_SECURE_INTERRUPTS_DISABLED,
    VIRT_DRTM_SECURE_INTERRUPTS_REENABLED,
} VirtDRTMSecureInterruptState;

typedef struct VirtDRTMWorkflow {
    VirtDRTMPhase phase;
    VirtDRTMLocalityState locality[4];
    VirtDRTMProtectionState protection;
    VirtDRTMSecureInterruptState secure_interrupts;
    bool protection_release_available;
    bool error_set_this_launch;
    uint64_t sticky_error;
    uint64_t launch_sequence;
} VirtDRTMWorkflow;

typedef struct VirtDRTMPreflightInput {
    bool caller_aarch64;
    bool caller_is_boot_pe;
    bool secondary_pes_off;
    bool no_active_tpm_locality;
    uint32_t supported_launch_features;
    VirtDRTMParamStatus parameter_status;
    const VirtDRTMParameters *parameters;
    const VirtDRTMEventLogInput *event_log;
    const VirtDRTMDataInput *data;
} VirtDRTMPreflightInput;

typedef enum VirtDRTMPlannedEffect {
    VIRT_DRTM_EFFECT_OPEN_LOCALITIES = 1U << 0,
    VIRT_DRTM_EFFECT_BUILD_SOFTWARE_MEASUREMENTS = 1U << 1,
    VIRT_DRTM_EFFECT_PROTECT_MEMORY = 1U << 2,
    VIRT_DRTM_EFFECT_DISABLE_SECURE_INTERRUPTS = 1U << 3,
    VIRT_DRTM_EFFECT_WRITE_DLME_DATA = 1U << 4,
    VIRT_DRTM_EFFECT_CLOSE_LOCALITY_3 = 1U << 5,
    VIRT_DRTM_EFFECT_ACTIVATE_LOCALITY_2 = 1U << 6,
    VIRT_DRTM_EFFECT_CLEAR_ERROR = 1U << 7,
    VIRT_DRTM_EFFECT_ENTER_DLME = 1U << 8,
} VirtDRTMPlannedEffect;

typedef struct VirtDRTMLaunchPlanInfo {
    uint64_t expected_launch_sequence;
    uint32_t effects;
    uint64_t dlme_address;
    uint64_t data_offset;
    uint64_t entry_address;
    uint8_t memory_protection;
    bool disable_secure_interrupts;
    const uint8_t *event_log;
    size_t event_log_size;
    const uint8_t *dlme_data;
    size_t dlme_data_size;
} VirtDRTMLaunchPlanInfo;

typedef struct VirtDRTMLaunchPlan VirtDRTMLaunchPlan;

void virt_drtm_workflow_init(VirtDRTMWorkflow *workflow);
void virt_drtm_workflow_reset(VirtDRTMWorkflow *workflow);

/*
 * Reconcile a successful authoritative TPM observation with the software
 * lifecycle.  A DLME can relinquish locality 2 through TPM MMIO, without an
 * SMC that would otherwise update this model.
 */
void virt_drtm_workflow_observe_no_active_locality(
    VirtDRTMWorkflow *workflow);

/*
 * Build an immutable launch transaction without changing workflow or guest
 * state.  Checks have a stable order: lifecycle, caller, secondary PEs, TPM
 * locality, decoded parameters/features, event log, then DLME data.
 */
VirtDRTMResult virt_drtm_workflow_preflight(
    const VirtDRTMWorkflow *workflow, const VirtDRTMPreflightInput *input,
    VirtDRTMLaunchPlan **plan);
void virt_drtm_launch_plan_free(VirtDRTMLaunchPlan *plan);
const VirtDRTMLaunchPlanInfo *virt_drtm_launch_plan_info(
    const VirtDRTMLaunchPlan *plan);
const VirtDRTMMeasurementManifest *virt_drtm_launch_plan_manifest(
    const VirtDRTMLaunchPlan *plan);

VirtDRTMResult virt_drtm_workflow_begin(VirtDRTMWorkflow *workflow,
                                        const VirtDRTMLaunchPlan *plan);
VirtDRTMResult virt_drtm_workflow_open_localities(VirtDRTMWorkflow *workflow);
VirtDRTMResult virt_drtm_workflow_enter_dce(VirtDRTMWorkflow *workflow);
VirtDRTMResult virt_drtm_workflow_activate_locality2(
    VirtDRTMWorkflow *workflow);
VirtDRTMResult virt_drtm_workflow_enter_dlme(VirtDRTMWorkflow *workflow);
VirtDRTMResult virt_drtm_workflow_relinquish_locality(
    VirtDRTMWorkflow *workflow, unsigned int locality);
VirtDRTMResult virt_drtm_workflow_close_locality(
    VirtDRTMWorkflow *workflow, unsigned int locality);
VirtDRTMResult virt_drtm_workflow_unprotect(VirtDRTMWorkflow *workflow);
VirtDRTMResult virt_drtm_workflow_enable_secure_interrupts(
    VirtDRTMWorkflow *workflow);
uint64_t virt_drtm_workflow_get_error(const VirtDRTMWorkflow *workflow);
VirtDRTMResult virt_drtm_workflow_set_error(VirtDRTMWorkflow *workflow,
                                            uint64_t error);

/* Internal non-returning failure path: it never represents an SMC return. */
void virt_drtm_workflow_remediate(VirtDRTMWorkflow *workflow,
                                  uint8_t error_id);

/* All workflow, plan, input, and output pointers are internal non-NULL APIs. */

#endif
