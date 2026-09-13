/*
 * Arm DRTM firmware measurement manifest
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_MEASUREMENT_H
#define HW_ARM_VIRT_DRTM_MEASUREMENT_H

#include "hw/arm/virt-drtm-event-log.h"

#define VIRT_DRTM_TPM_ALG_SHA1   0x0004
#define VIRT_DRTM_TPM_ALG_SHA256 0x000b
#define VIRT_DRTM_TPM_ALG_SHA384 0x000c
#define VIRT_DRTM_TPM_ALG_SHA512 0x000d
#define VIRT_DRTM_MAX_PCR_BANKS  4
#define VIRT_DRTM_MAX_DIGEST_SIZE 64

typedef struct VirtDRTMDigest {
    uint16_t algorithm;
    uint16_t size;
    uint8_t value[VIRT_DRTM_MAX_DIGEST_SIZE];
} VirtDRTMDigest;

typedef struct VirtDRTMMeasurementEvent {
    uint32_t pcr;
    uint32_t type;
    const VirtDRTMDigest *digests;
    size_t digest_count;
    VirtDRTMBlob event_data;
} VirtDRTMMeasurementEvent;

typedef enum VirtDRTMMeasurementOperationType {
    VIRT_DRTM_MEASUREMENT_HASH_START,
    VIRT_DRTM_MEASUREMENT_HASH_DATA,
    VIRT_DRTM_MEASUREMENT_HASH_END,
    VIRT_DRTM_MEASUREMENT_PCR_CAP,
    VIRT_DRTM_MEASUREMENT_PCR_EXTEND,
} VirtDRTMMeasurementOperationType;

typedef struct VirtDRTMMeasurementOperation {
    VirtDRTMMeasurementOperationType type;
    uint32_t pcr;
    VirtDRTMDigest digest;
} VirtDRTMMeasurementOperation;

typedef struct VirtDRTMMeasurementManifest VirtDRTMMeasurementManifest;

/* Select the DEN0113 R48000 firmware algorithm from enabled PCR banks. */
VirtDRTMEventLogStatus virt_drtm_firmware_hash_select(
    const uint16_t *active_banks, size_t active_bank_count,
    uint16_t *selected_algorithm);

VirtDRTMEventLogStatus virt_drtm_measurement_manifest_build(
    const VirtDRTMEventLogInput *input, VirtDRTMMeasurementManifest **result);
/* A successful manifest owns its digest and event-data bytes. */
void virt_drtm_measurement_manifest_free(VirtDRTMMeasurementManifest *manifest);

uint16_t virt_drtm_measurement_manifest_algorithm(
    const VirtDRTMMeasurementManifest *manifest);
size_t virt_drtm_measurement_manifest_bank_count(
    const VirtDRTMMeasurementManifest *manifest);
uint16_t virt_drtm_measurement_manifest_bank(
    const VirtDRTMMeasurementManifest *manifest, size_t index);
size_t virt_drtm_measurement_manifest_event_count(
    const VirtDRTMMeasurementManifest *manifest);
const VirtDRTMMeasurementEvent *virt_drtm_measurement_manifest_event(
    const VirtDRTMMeasurementManifest *manifest, size_t index);
size_t virt_drtm_measurement_manifest_operation_count(
    const VirtDRTMMeasurementManifest *manifest);
/* First operation owned by the DCE; preceding operations are D-CRTM-owned. */
size_t virt_drtm_measurement_manifest_dce_operation(
    const VirtDRTMMeasurementManifest *manifest);
const VirtDRTMMeasurementOperation *virt_drtm_measurement_manifest_operation(
    const VirtDRTMMeasurementManifest *manifest, size_t index);

#endif
