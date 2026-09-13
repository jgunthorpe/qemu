/*
 * Arm DRTM mutable TCB hash store
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_TCB_H
#define HW_ARM_VIRT_DRTM_TCB_H

#include "hw/arm/virt-drtm-data.h"

#define VIRT_DRTM_TCB_MAX_HASHES       255
#define VIRT_DRTM_TCB_MAX_DIGEST_SIZE  64

typedef enum VirtDRTMTCBStatus {
    VIRT_DRTM_TCB_SUCCESS,
    VIRT_DRTM_TCB_INVALID_PARAMETERS,
    VIRT_DRTM_TCB_INVALID_DATA,
    VIRT_DRTM_TCB_OUT_OF_RESOURCE,
    VIRT_DRTM_TCB_DENIED,
    /* R45290: a nonempty hash set must be locked before launch. */
    VIRT_DRTM_TCB_NOT_LOCKED,
} VirtDRTMTCBStatus;

typedef struct VirtDRTMTCBResult {
    VirtDRTMTCBStatus status;
    /* Success: accepted count.  INVALID_DATA: zero-based bad entry index. */
    uint64_t supplemental;
} VirtDRTMTCBResult;

typedef struct VirtDRTMStoredTCBHash {
    uint32_t id;
    uint8_t digest[VIRT_DRTM_TCB_MAX_DIGEST_SIZE];
} VirtDRTMStoredTCBHash;

typedef struct VirtDRTMTCBStore {
    uint16_t algorithm;
    uint8_t capacity;
    uint8_t count;
    bool locked;
    VirtDRTMStoredTCBHash hashes[VIRT_DRTM_TCB_MAX_HASHES];
} VirtDRTMTCBStore;

/* TPM_ALG_SHA256, TPM_ALG_SHA384, and TPM_ALG_SHA512 are supported. */
bool virt_drtm_tcb_init(VirtDRTMTCBStore *store, uint16_t algorithm,
                        unsigned int capacity);
void virt_drtm_tcb_reset(VirtDRTMTCBStore *store);

/*
 * Atomically append a revision-1 TCB_HASH_TABLE copied from guest memory.
 * The input must contain exactly the header and declared entries.  A short
 * entry area models a guest-memory read failure and identifies the first
 * incomplete entry through supplemental.
 */
VirtDRTMTCBResult virt_drtm_tcb_set(VirtDRTMTCBStore *store,
                                    const uint8_t *table, size_t table_size);
VirtDRTMTCBStatus virt_drtm_tcb_lock(VirtDRTMTCBStore *store);

/*
 * Snapshot borrowed views for launch construction, including an unlocked
 * set.  ready reports the R45290 lock condition separately so the launch
 * transaction can enforce it in the architected post-D-CRTM phase.
 */
VirtDRTMTCBStatus virt_drtm_tcb_snapshot(const VirtDRTMTCBStore *store,
                                         VirtDRTMTCBHash *hashes,
                                         size_t capacity, bool *ready);

/* Export borrowed views suitable for a launch's VirtDRTMDataInput. */
VirtDRTMTCBStatus virt_drtm_tcb_export(const VirtDRTMTCBStore *store,
                                       VirtDRTMTCBHash *hashes,
                                       size_t capacity);

#endif
