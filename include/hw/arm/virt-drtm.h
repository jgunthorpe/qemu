/*
 * Arm virt DRTM firmware service
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_H
#define HW_ARM_VIRT_DRTM_H

#include "qom/object.h"
#include "hw/core/resettable.h"
#include "hw/arm/virt-drtm-tcb.h"
#include "hw/arm/virt-drtm-launch.h"
#include "hw/arm/virt-drtm-workflow.h"
#include "hw/arm/virt-drtm-tpm.h"

typedef struct Error Error;
typedef struct ArchCPU ARMCPU;

#define TYPE_VIRT_DRTM "virt-drtm"
OBJECT_DECLARE_SIMPLE_TYPE(VirtDRTMState, VIRT_DRTM)

#define VIRT_DRTM_TCB_HASH_CAPACITY 64

struct VirtDRTMState {
    Object parent_obj;

    /* State reserved for the complete workflow implementation. */
    bool routes_registered;
    bool enabled;
    VirtDRTMWorkflow workflow;
    VirtDRTMTCBStore tcb_hashes;
    bool tpm_ready;
#ifdef CONFIG_TPM
    TPMIf *tpm;
    bool tpm_drtm_enabled;
    uint16_t active_banks[VIRT_DRTM_MAX_PCR_BANKS];
    size_t active_bank_count;
    uint16_t firmware_hash_algorithm;
#endif
    Error *migration_blocker;
    ResettableState reset_state;
    bool reset_registered;
};

/* Register immutable CPU-side SMC routing while the machine is being built. */
bool virt_drtm_register_routes(VirtDRTMState *s, Error **errp);

/* Bind late-created TPM state and publish the service before initial reset. */
bool virt_drtm_start(VirtDRTMState *s, Error **errp);

/* Execute the complete production launch transaction. */
VirtDRTMLaunchResult virt_drtm_service_launch(VirtDRTMState *s, ARMCPU *cpu,
                                               uint64_t parameters_address,
                                               Error **errp);

#endif
