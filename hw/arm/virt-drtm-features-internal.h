/*
 * Arm virt DRTM feature-query internals
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_FEATURES_INTERNAL_H
#define HW_ARM_VIRT_DRTM_FEATURES_INTERNAL_H

#include "hw/arm/virt-drtm.h"

#define VIRT_DRTM_FEATURE_QUERY_FLAG (UINT64_C(1) << 63)

#define VIRT_DRTM_FEATURE_TPM                 0x01
#define VIRT_DRTM_FEATURE_MINIMUM_MEMORY      0x02
#define VIRT_DRTM_FEATURE_DMA_PROTECTION      0x03
#define VIRT_DRTM_FEATURE_BOOT_PE             0x04
#define VIRT_DRTM_FEATURE_TCB_HASH            0x05
#define VIRT_DRTM_FEATURE_IMAGE_AUTHENTICATION 0x06

/*
 * Stable serialization resource limit for the platform address map.  This is
 * deliberately a capacity contract, not a statement about security or the
 * number of ranges present in any one FlatView snapshot.
 */
#define VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS 4096

typedef struct VirtDRTMFeaturesResult {
    int64_t x0;
    bool has_x1;
    uint64_t x1;
} VirtDRTMFeaturesResult;

/* The launch decoder and FEATURES encoder share this exact profile. */
void virt_drtm_features_capabilities(VirtDRTMCapabilities *capabilities,
                                     uint32_t *supported_launch_features);

bool virt_drtm_features_launch_capabilities(
    const VirtDRTMState *s, size_t address_map_capacity,
    VirtDRTMCapabilities *capabilities, uint32_t *supported_launch_features);

/*
 * Construct a Table 6 response from immutable service state.  boot_pe_id is
 * the PSCI target_cpu/MPIDR affinity encoding, not a QEMU CPU index.  The map
 * capacity is an upper bound on descriptors from the authoritative FlatView
 * snapshot and makes the advertised minimum data size sufficient for the
 * maximum payload the current launch profile can serialize.
 */
VirtDRTMFeaturesResult virt_drtm_features_query(const VirtDRTMState *s,
                                                uint64_t boot_pe_id,
                                                size_t address_map_capacity,
                                                uint64_t query);

#endif
