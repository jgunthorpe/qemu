/*
 * Arm DRTM launch parameter decoder
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_PARAMS_H
#define HW_ARM_VIRT_DRTM_PARAMS_H

#include "qemu/compiler.h"

#define VIRT_DRTM_PARAMETERS_SIZE 88

typedef enum VirtDRTMParamStatus {
    VIRT_DRTM_PARAM_SUCCESS = 0,
    VIRT_DRTM_INVALID_PARAMETERS = -2,
    VIRT_DRTM_MEM_PROTECT_INVALID = -6,
    VIRT_DRTM_OUT_OF_RESOURCE = -8,
} VirtDRTMParamStatus;

typedef bool (*VirtDRTMReadFn)(void *opaque, uint64_t address,
                               void *buffer, size_t size);
typedef bool (*VirtDRTMIsRamFn)(void *opaque, uint64_t address, uint64_t size);

typedef struct VirtDRTMCapabilities {
    uint8_t memory_protection_mask;
    uint8_t pcr_schema_mask;
    uint16_t maximum_protected_regions;
    uint32_t minimum_dlme_data_pages;
    uint32_t minimum_dce_pages;
    bool tpm_hashing;
    bool image_authentication;
    bool disable_secure_interrupts;
} VirtDRTMCapabilities;

typedef struct VirtDRTMProtectedRegion {
    uint64_t address;
    uint64_t size;
} VirtDRTMProtectedRegion;

/*
 * A successfully returned descriptor is an owned, normalized snapshot.  It is
 * read-only to its caller and remains valid until virt_drtm_params_free().
 */
typedef struct VirtDRTMParameters {
    uint32_t launch_features;
    uint8_t memory_protection;
    uint8_t pcr_schema;
    bool tpm_hashing;
    bool image_authentication;
    bool disable_secure_interrupts;

    uint64_t dlme_address;
    uint64_t dlme_size;
    uint64_t image_address;
    uint64_t image_size;
    uint64_t entry_address;
    uint64_t data_address;
    uint64_t data_offset;

    bool has_dce;
    uint64_t dce_address;
    uint64_t dce_size;

    uint64_t protection_table_address;
    uint64_t protection_table_size;
    uint32_t protected_region_count;
    const VirtDRTMProtectedRegion *protected_regions;
} VirtDRTMParameters;

/*
 * DEN0113 does not define priority when multiple independent errors exist.
 * This decoder deterministically checks parameter fetch/layout, feature
 * encodings/capabilities, DLME/DCE ranges, and cross-range overlap in that
 * order.  Once a region table is specified, table fetch/layout, descriptor
 * fields/RAM classification, descriptor overlap, and required coverage follow.
 * result must be non-NULL.
 */
VirtDRTMParamStatus virt_drtm_params_decode(
    uint64_t parameters_address, const VirtDRTMCapabilities *capabilities,
    VirtDRTMReadFn read, VirtDRTMIsRamFn is_ram, void *opaque,
    const VirtDRTMParameters **result);

void virt_drtm_params_free(const VirtDRTMParameters *parameters);

#endif
