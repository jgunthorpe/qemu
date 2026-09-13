/*
 * Arm DRTM mutable TCB hash store
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/arm/virt-drtm-tcb.h"
#include "qemu/bswap.h"

#define TCB_TABLE_HEADER_SIZE 8
#define TPM_ALG_SHA256 0x000b
#define TPM_ALG_SHA384 0x000c
#define TPM_ALG_SHA512 0x000d

static size_t digest_size(uint16_t algorithm)
{
    switch (algorithm) {
    case TPM_ALG_SHA256:
        return 32;
    case TPM_ALG_SHA384:
        return 48;
    case TPM_ALG_SHA512:
        return 64;
    default:
        return 0;
    }
}

bool virt_drtm_tcb_init(VirtDRTMTCBStore *store, uint16_t algorithm,
                        unsigned int capacity)
{
    g_assert(store);
    if (!digest_size(algorithm) || capacity > VIRT_DRTM_TCB_MAX_HASHES) {
        return false;
    }
    memset(store, 0, sizeof(*store));
    store->algorithm = algorithm;
    store->capacity = capacity;
    return true;
}

void virt_drtm_tcb_reset(VirtDRTMTCBStore *store)
{
    uint16_t algorithm;
    uint8_t capacity;

    g_assert(store);
    algorithm = store->algorithm;
    capacity = store->capacity;
    memset(store, 0, sizeof(*store));
    store->algorithm = algorithm;
    store->capacity = capacity;
}

VirtDRTMTCBResult virt_drtm_tcb_set(VirtDRTMTCBStore *store,
                                    const uint8_t *table, size_t table_size)
{
    VirtDRTMTCBResult result = { VIRT_DRTM_TCB_INVALID_PARAMETERS, 0 };
    size_t hash_size, entry_size, expected_size, available_entries;
    unsigned int table_count, i;

    g_assert(store);
    if (store->locked) {
        result.status = VIRT_DRTM_TCB_DENIED;
        return result;
    }
    if (!table || table_size < TCB_TABLE_HEADER_SIZE) {
        return result;
    }

    hash_size = digest_size(store->algorithm);
    table_count = lduw_le_p(table + 2);
    if (lduw_le_p(table) != 1 || !table_count ||
        lduw_le_p(table + 4) != store->algorithm ||
        lduw_le_p(table + 6)) {
        return result;
    }
    if (table_count > store->capacity - store->count) {
        result.status = VIRT_DRTM_TCB_OUT_OF_RESOURCE;
        return result;
    }
    entry_size = sizeof(uint32_t) + hash_size;
    expected_size = TCB_TABLE_HEADER_SIZE + table_count * entry_size;
    if (table_size < expected_size) {
        available_entries = (table_size - TCB_TABLE_HEADER_SIZE) / entry_size;
        result.status = VIRT_DRTM_TCB_INVALID_DATA;
        result.supplemental = MIN(available_entries, table_count - 1);
        return result;
    }
    if (table_size != expected_size) {
        return result;
    }
    for (i = 0; i < table_count; i++) {
        const uint8_t *entry = table + TCB_TABLE_HEADER_SIZE + i * entry_size;
        VirtDRTMStoredTCBHash *hash = &store->hashes[store->count + i];

        /* R315010: discard the caller's Source of Entry bit. */
        hash->id = ldl_le_p(entry) & ~UINT32_C(0x80000000);
        memcpy(hash->digest, entry + sizeof(uint32_t), hash_size);
    }
    store->count += table_count;
    result.status = VIRT_DRTM_TCB_SUCCESS;
    result.supplemental = table_count;
    return result;
}

VirtDRTMTCBStatus virt_drtm_tcb_lock(VirtDRTMTCBStore *store)
{
    g_assert(store);
    if (store->locked) {
        return VIRT_DRTM_TCB_DENIED;
    }
    store->locked = true;
    return VIRT_DRTM_TCB_SUCCESS;
}

VirtDRTMTCBStatus virt_drtm_tcb_snapshot(const VirtDRTMTCBStore *store,
                                         VirtDRTMTCBHash *hashes,
                                         size_t capacity, bool *ready)
{
    size_t size;
    unsigned int i;

    g_assert(store);
    if (!ready || capacity < store->count || (store->count && !hashes)) {
        return VIRT_DRTM_TCB_INVALID_PARAMETERS;
    }
    *ready = !store->count || store->locked;
    size = digest_size(store->algorithm);
    for (i = 0; i < store->count; i++) {
        hashes[i] = (VirtDRTMTCBHash) {
            .id = store->hashes[i].id,
            .digest = store->hashes[i].digest,
            .digest_size = size,
            .origin = VIRT_DRTM_TCB_HASH_SET_TCB_HASH,
        };
    }
    return VIRT_DRTM_TCB_SUCCESS;
}

VirtDRTMTCBStatus virt_drtm_tcb_export(const VirtDRTMTCBStore *store,
                                       VirtDRTMTCBHash *hashes,
                                       size_t capacity)
{
    bool ready;
    VirtDRTMTCBStatus status;

    g_assert(store);
    if (store->count && !store->locked) {
        return VIRT_DRTM_TCB_NOT_LOCKED;
    }
    status = virt_drtm_tcb_snapshot(store, hashes, capacity, &ready);
    if (status != VIRT_DRTM_TCB_SUCCESS) {
        return status;
    }
    g_assert(ready);
    return VIRT_DRTM_TCB_SUCCESS;
}
