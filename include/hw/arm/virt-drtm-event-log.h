/*
 * Arm DRTM crypto-agile event log serializer
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_EVENT_LOG_H
#define HW_ARM_VIRT_DRTM_EVENT_LOG_H

#include "hw/arm/virt-drtm-data.h"

#define VIRT_DRTM_EV_ARM_BASE                0x9000
#define VIRT_DRTM_EV_PCR_SCHEMA              0x9001
#define VIRT_DRTM_EV_DCE                     0x9002
#define VIRT_DRTM_EV_DCE_PUBKEY              0x9003
#define VIRT_DRTM_EV_DLME                    0x9004
#define VIRT_DRTM_EV_DLME_ENTRY_POINT        0x9005
#define VIRT_DRTM_EV_DEBUG_CONFIG            0x9006
#define VIRT_DRTM_EV_NONSECURE_CONFIG        0x9007
#define VIRT_DRTM_EV_TZFW                    0x9009
#define VIRT_DRTM_EV_SEPARATOR               0x900a
#define VIRT_DRTM_EV_SECURE_INT_DISABLE      0x900e

typedef struct VirtDRTMMeasuredComponent {
    VirtDRTMBlob image;
    /* Implementation-defined identifying data for the TZFW component. */
    VirtDRTMBlob event_data;
} VirtDRTMMeasuredComponent;

typedef struct VirtDRTMEventLogInput {
    /* Enabled SHA-1/256/384/512 PCR banks, each a unique TPM_ALG_ID. */
    const uint16_t *active_banks;
    size_t active_bank_count;
    /*
     * Exact one-byte schema bitmap value measured by DEN0113 Table 19 (for
     * example 0x01 for the default schema), not the parameter-field ordinal.
     */
    uint8_t pcr_schema_value;

    /* A zero-size DCE denotes the architected non-distinct DCE case. */
    VirtDRTMBlob dce_image;
    VirtDRTMBlob dce_public_key;
    VirtDRTMBlob dce_certificate_chain;

    const VirtDRTMMeasuredComponent *tzfw;
    size_t tzfw_count;
    bool secure_interrupts_disabled;

    bool debug_or_trace_enabled;
    bool nonsecure_lifecycle;
    VirtDRTMBlob dlme_image;
    uint64_t dlme_entry_point_offset;
} VirtDRTMEventLogInput;

typedef enum VirtDRTMEventLogStatus {
    VIRT_DRTM_EVENT_LOG_OK,
    VIRT_DRTM_EVENT_LOG_INVALID,
    VIRT_DRTM_EVENT_LOG_TOO_SMALL,
    VIRT_DRTM_EVENT_LOG_OVERFLOW,
    VIRT_DRTM_EVENT_LOG_HASH_ERROR,
} VirtDRTMEventLogStatus;

/* Passing output == NULL computes the exact required size. */
VirtDRTMEventLogStatus virt_drtm_event_log_build(
    const VirtDRTMEventLogInput *input, uint8_t *output, size_t output_size,
    size_t *required_size);

#endif
