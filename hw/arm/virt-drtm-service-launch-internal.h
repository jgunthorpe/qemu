/*
 * Arm virt DRTM private launch dependency boundary
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_SERVICE_LAUNCH_INTERNAL_H
#define HW_ARM_VIRT_DRTM_SERVICE_LAUNCH_INTERNAL_H

#include "hw/arm/virt-drtm-launch.h"
#include "hw/arm/virt-drtm-params.h"

typedef struct VirtDRTMState VirtDRTMState;

typedef struct VirtDRTMServiceLaunchOps {
    VirtDRTMReadFn read;
    VirtDRTMIsRamFn is_ram;
    /* All returned storage must be compatible with g_free(). */
    void *(*alloc)(size_t size);
    /* Return a g_free()-owned, complete Normal-world address-map snapshot. */
    VirtDRTMResult (*snapshot_address_map)(void *opaque,
                                           VirtDRTMMemoryRegion **regions,
                                           size_t *count);
    /* Validate and retain the manifest without producing a TPM effect. */
    bool (*prepare_tpm)(void *opaque,
                        const VirtDRTMMeasurementManifest *manifest,
                        Error **errp);
    VirtDRTMLaunchOps launch;
    bool debug_or_trace_enabled;
    bool nonsecure_lifecycle;
} VirtDRTMServiceLaunchOps;

VirtDRTMLaunchResult virt_drtm_service_launch_with_ops(
    VirtDRTMState *s, uint64_t parameters_address, bool caller_aarch64,
    bool caller_is_boot_pe, bool secondary_pes_off,
    size_t address_map_capacity,
    const VirtDRTMServiceLaunchOps *ops, void *opaque, Error **errp);

#endif
