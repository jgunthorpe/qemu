/*
 * Arm virt DRTM SMC dispatch
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "qemu/bswap.h"
#include "virt-drtm-smc-internal.h"

#define TCB_HASH_TABLE_HEADER_SIZE 8
#define DRTM_VERSION_1_4 ((1U << 16) | 4U)

static size_t tcb_digest_size(uint16_t algorithm)
{
    switch (algorithm) {
    case 0x000b: /* TPM_ALG_SHA256 */
        return 32;
    case 0x000c: /* TPM_ALG_SHA384 */
        return 48;
    case 0x000d: /* TPM_ALG_SHA512 */
        return 64;
    default:
        return 0;
    }
}

static VirtDRTMSMCResult result(VirtDRTMResult status)
{
    return (VirtDRTMSMCResult) { .status = status };
}

static bool feature_needs_tpm_ready(uint64_t query)
{
    uint8_t feature = query;

    return (query & VIRT_DRTM_FEATURE_QUERY_FLAG) &&
           !(query & MAKE_64BIT_MASK(8, 55)) &&
           (feature == VIRT_DRTM_FEATURE_TPM ||
            feature == VIRT_DRTM_FEATURE_MINIMUM_MEMORY);
}

static bool ensure_ready(VirtDRTMState *s, const VirtDRTMSMCOps *ops,
                         void *opaque, Error **errp)
{
    return s->tpm_ready ||
           (ops && ops->ensure_ready && ops->ensure_ready(opaque, errp));
}

static VirtDRTMResult tcb_status(VirtDRTMTCBStatus status)
{
    switch (status) {
    case VIRT_DRTM_TCB_SUCCESS:
        return VIRT_DRTM_SUCCESS;
    case VIRT_DRTM_TCB_INVALID_PARAMETERS:
        return VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS;
    case VIRT_DRTM_TCB_INVALID_DATA:
        return VIRT_DRTM_INVALID_DATA;
    case VIRT_DRTM_TCB_OUT_OF_RESOURCE:
        return VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE;
    case VIRT_DRTM_TCB_DENIED:
    case VIRT_DRTM_TCB_NOT_LOCKED:
        return VIRT_DRTM_DENIED;
    default:
        return VIRT_DRTM_INTERNAL_ERROR;
    }
}

static VirtDRTMSMCResult set_tcb_hash(VirtDRTMState *s, uint64_t address,
                                      const VirtDRTMSMCOps *ops,
                                      void *opaque)
{
    uint8_t header[TCB_HASH_TABLE_HEADER_SIZE];
    VirtDRTMTCBResult set_result;
    uint8_t *table;
    size_t digest_size, entry_size, table_size;
    unsigned int count, i;

    if (s->workflow.phase != VIRT_DRTM_PHASE_READY || s->tcb_hashes.locked) {
        return result(VIRT_DRTM_DENIED);
    }
    if (address > UINT64_MAX - (sizeof(header) - 1) ||
        !ops || !ops->guest_is_ram || !ops->read_guest ||
        !ops->guest_is_ram(opaque, address, sizeof(header)) ||
        !ops->read_guest(opaque, address, header, sizeof(header))) {
        return result(VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    }

    count = lduw_le_p(header + 2);
    digest_size = tcb_digest_size(s->tcb_hashes.algorithm);
    if (lduw_le_p(header) != 1 || !count ||
        lduw_le_p(header + 4) != s->tcb_hashes.algorithm ||
        lduw_le_p(header + 6) || !digest_size) {
        return result(VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    }
    if (count > s->tcb_hashes.capacity - s->tcb_hashes.count) {
        return result(VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
    }

    entry_size = sizeof(uint32_t) + digest_size;
    if (count > (SIZE_MAX - sizeof(header)) / entry_size) {
        return result(VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
    }
    table_size = sizeof(header) + count * entry_size;
    if (address > UINT64_MAX - (table_size - 1)) {
        return result(VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    }
    if (!ops->guest_is_ram(opaque, address, table_size)) {
        return result(VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    }
    table = g_try_malloc(table_size);
    if (!table) {
        return result(VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
    }
    memcpy(table, header, sizeof(header));
    for (i = 0; i < count; i++) {
        size_t offset = sizeof(header) + i * entry_size;

        if (!ops->read_guest(opaque, address + offset, table + offset,
                             entry_size)) {
            g_free(table);
            return (VirtDRTMSMCResult) {
                .status = VIRT_DRTM_INVALID_DATA,
                .has_x1 = true,
                .x1 = i,
            };
        }
    }

    set_result = virt_drtm_tcb_set(&s->tcb_hashes, table, table_size);
    g_free(table);
    return (VirtDRTMSMCResult) {
        .status = tcb_status(set_result.status),
        .has_x1 = set_result.status == VIRT_DRTM_TCB_SUCCESS ||
                  set_result.status == VIRT_DRTM_TCB_INVALID_DATA,
        .x1 = set_result.supplemental,
    };
}

static VirtDRTMSMCResult close_locality(VirtDRTMState *s, uint32_t locality,
                                        const VirtDRTMSMCOps *ops,
                                        void *opaque, Error **errp)
{
    TPMDRTMLocalityCloseResult close_result;
    VirtDRTMResult status;

    if (locality != 2 && locality != 3) {
        return result(VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    }
    if (s->workflow.locality[locality] == VIRT_DRTM_LOCALITY_CLOSED) {
        return result(VIRT_DRTM_ALREADY_CLOSED);
    }
    if ((locality == 2 && s->workflow.phase != VIRT_DRTM_PHASE_DLME) ||
        (locality == 3 && s->workflow.phase != VIRT_DRTM_PHASE_DCE)) {
        return result(VIRT_DRTM_DENIED);
    }
    if (!ops || !ops->close_locality ||
        !ops->close_locality(opaque, locality, &close_result, errp)) {
        return result(VIRT_DRTM_TPM_ERROR);
    }
    switch (close_result) {
    case TPM_DRTM_LOCALITY_ALREADY_CLOSED:
        return result(VIRT_DRTM_ALREADY_CLOSED);
    case TPM_DRTM_LOCALITY_NOT_RELINQUISHED:
        return result(VIRT_DRTM_DENIED);
    case TPM_DRTM_LOCALITY_CLOSED:
        break;
    default:
        return result(VIRT_DRTM_INTERNAL_ERROR);
    }

    if (s->workflow.locality[locality] !=
        VIRT_DRTM_LOCALITY_RELINQUISHED) {
        status = virt_drtm_workflow_relinquish_locality(&s->workflow,
                                                        locality);
        if (status != VIRT_DRTM_SUCCESS) {
            return result(VIRT_DRTM_INTERNAL_ERROR);
        }
    }
    status = virt_drtm_workflow_close_locality(&s->workflow, locality);
    return result(status == VIRT_DRTM_SUCCESS ? status :
                  VIRT_DRTM_INTERNAL_ERROR);
}

VirtDRTMSMCResult virt_drtm_smc_dispatch_with_ops(
    VirtDRTMState *s, bool caller_aarch64, uint32_t function, uint64_t x1,
    const VirtDRTMSMCOps *ops, void *opaque, Error **errp)
{
    VirtDRTMResult status;
    bool dce;

    g_assert(s);
    if (!caller_aarch64) {
        return result(function == DRTM_DYNAMIC_LAUNCH ?
                      VIRT_DRTM_DENIED : VIRT_DRTM_NOT_SUPPORTED);
    }

    switch (function) {
    case DRTM_VERSION:
        return result((VirtDRTMResult)DRTM_VERSION_1_4);
    case DRTM_FEATURES: {
        VirtDRTMFeaturesResult features;

        /* Function-availability queries are immutable publication state. */
        if (feature_needs_tpm_ready(x1) &&
            !ensure_ready(s, ops, opaque, errp)) {
            return result(VIRT_DRTM_TPM_ERROR);
        }
        if (!ops || !ops->features) {
            return result(VIRT_DRTM_INTERNAL_ERROR);
        }
        features = ops->features(opaque, x1);
        return (VirtDRTMSMCResult) {
            .status = (VirtDRTMResult)features.x0,
            .has_x1 = features.has_x1,
            .x1 = features.x1,
        };
    }
    case DRTM_DYNAMIC_LAUNCH: {
        VirtDRTMLaunchResult launch;

        if (!ensure_ready(s, ops, opaque, errp)) {
            return result(VIRT_DRTM_TPM_ERROR);
        }
        if (!ops || !ops->dynamic_launch) {
            return result(VIRT_DRTM_INTERNAL_ERROR);
        }
        launch = ops->dynamic_launch(opaque, x1, errp);
        return (VirtDRTMSMCResult) {
            .status = launch.result,
            .non_returning = launch.non_returning,
            .launch_stage = launch.stage,
        };
    }
    case DRTM_UNPROTECT_MEMORY:
        return result(virt_drtm_workflow_unprotect(&s->workflow));
    case DRTM_CLOSE_LOCALITY:
        return close_locality(s, (uint32_t)x1, ops, opaque, errp);
    case DRTM_GET_ERROR:
        return (VirtDRTMSMCResult) {
            .status = VIRT_DRTM_SUCCESS,
            .has_x1 = true,
            .x1 = virt_drtm_workflow_get_error(&s->workflow),
        };
    case DRTM_SET_ERROR:
        dce = s->workflow.phase == VIRT_DRTM_PHASE_DCE;
        if (dce && (!ops || !ops->request_cold_reset)) {
            return result(VIRT_DRTM_INTERNAL_ERROR);
        }
        status = virt_drtm_workflow_set_error(&s->workflow, x1);
        if (status == VIRT_DRTM_SUCCESS && dce) {
            ops->request_cold_reset(opaque);
        }
        return result(status);
    case DRTM_SET_TCB_HASH:
        if (s->workflow.phase == VIRT_DRTM_PHASE_READY &&
            !ensure_ready(s, ops, opaque, errp)) {
            return result(VIRT_DRTM_TPM_ERROR);
        }
        return set_tcb_hash(s, x1, ops, opaque);
    case DRTM_LOCK_TCB_HASHES:
        if (s->workflow.phase != VIRT_DRTM_PHASE_READY) {
            return result(VIRT_DRTM_DENIED);
        }
        if (!ensure_ready(s, ops, opaque, errp)) {
            return result(VIRT_DRTM_TPM_ERROR);
        }
        return result(tcb_status(virt_drtm_tcb_lock(&s->tcb_hashes)));
    case DRTM_ENABLE_SECURE_INTERRUPTS:
        /* The virt model tracks the requested firmware dispatch state. */
        return result(virt_drtm_workflow_enable_secure_interrupts(
                          &s->workflow));
    default:
        return result(VIRT_DRTM_NOT_SUPPORTED);
    }
}
