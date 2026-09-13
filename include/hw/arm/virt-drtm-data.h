/*
 * Arm DRTM DLME data serializer
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_DATA_H
#define HW_ARM_VIRT_DRTM_DATA_H

#include "qemu/typedefs.h"

#define VIRT_DRTM_DATA_HEADER_SIZE 64
#define VIRT_DRTM_PAGE_SIZE        4096

typedef enum VirtDRTMMemoryType {
    VIRT_DRTM_MEMORY_NORMAL = 0,
    VIRT_DRTM_MEMORY_NORMAL_CACHED = 1,
    VIRT_DRTM_MEMORY_MMIO = 2,
    VIRT_DRTM_MEMORY_NON_VOLATILE = 3,
    VIRT_DRTM_MEMORY_UNUSABLE = 4,
} VirtDRTMMemoryType;

typedef struct VirtDRTMMemoryRegion {
    uint64_t address;
    uint64_t size;
    VirtDRTMMemoryType type;
    uint8_t cacheability;
} VirtDRTMMemoryRegion;

typedef struct VirtDRTMBlob {
    const uint8_t *data;
    size_t size;
} VirtDRTMBlob;

typedef enum VirtDRTMTCBHashOrigin {
    VIRT_DRTM_TCB_HASH_IMPLEMENTATION,
    VIRT_DRTM_TCB_HASH_SET_TCB_HASH,
} VirtDRTMTCBHashOrigin;

typedef struct VirtDRTMTCBHash {
    /* Bit 31 must be clear; the serializer assigns it from origin. */
    uint32_t id;
    const uint8_t *digest;
    size_t digest_size;
    VirtDRTMTCBHashOrigin origin;
} VirtDRTMTCBHash;

typedef enum VirtDRTMDataStatus {
    VIRT_DRTM_DATA_OK,
    VIRT_DRTM_DATA_INVALID,
    VIRT_DRTM_DATA_TOO_SMALL,
    VIRT_DRTM_DATA_OVERFLOW,
} VirtDRTMDataStatus;

typedef struct VirtDRTMDataInput {
    /* Launch geometry; the serializer validates alignment and containment. */
    uint64_t dlme_address;
    uint64_t dlme_size;
    uint64_t image_address;
    uint64_t image_size;

    bool complete_protection;
    const VirtDRTMMemoryRegion *protected_regions;
    size_t protected_region_count;

    /*
     * Complete caller-supplied Normal-world physical address map.  Discovering
     * the platform ranges is deliberately outside this pure serializer.
     */
    const VirtDRTMMemoryRegion *address_map;
    size_t address_map_count;

    /*
     * Exact used bytes returned by virt_drtm_event_log_build(); capacity is
     * not serialized.
     */
    VirtDRTMBlob event_log;

    /* The algorithm selected for firmware measurements (a TPM_ALG_ID). */
    uint16_t firmware_hash_algorithm;
    const VirtDRTMTCBHash *tcb_hashes;
    size_t tcb_hash_count;
} VirtDRTMDataInput;

/*
 * Serialize revision-1 DLME data.  output_address is the guest physical
 * address at which output[0] will reside.  The address map must be the complete
 * set acquired from the machine's authoritative platform-map provider; this
 * function validates its wire semantics and coverage of the complete DLME.
 * Passing output == NULL only computes the exact required size.
 */
VirtDRTMDataStatus virt_drtm_data_build(const VirtDRTMDataInput *input,
                                        uint64_t output_address,
                                        uint8_t *output, size_t output_size,
                                        size_t *required_size);

#endif
