/*
 * Arm DRTM crypto-agile event log serializer
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/arm/virt-drtm-measurement.h"
#include "qemu/bswap.h"

#define EV_NO_ACTION 0x00000003
#define LEGACY_HEADER_SIZE (4 + 4 + 20 + 4)
#define SPEC_FIXED_SIZE 29
#define EVENT2_FIXED_SIZE (4 + 4 + 4 + 4)

typedef struct EventWriter {
    uint8_t *output;
    size_t offset;
} EventWriter;

static bool add_size(size_t *total, size_t add)
{
    if (add > SIZE_MAX - *total) {
        return false;
    }
    *total += add;
    return true;
}

static VirtDRTMEventLogStatus event_size(
    const VirtDRTMMeasurementEvent *event, size_t *total)
{
    size_t size = EVENT2_FIXED_SIZE;
    size_t i;

    for (i = 0; i < event->digest_count; i++) {
        if (!add_size(&size, 2 + event->digests[i].size)) {
            return VIRT_DRTM_EVENT_LOG_OVERFLOW;
        }
    }
    if (!add_size(&size, event->event_data.size) ||
        !add_size(total, size)) {
        return VIRT_DRTM_EVENT_LOG_OVERFLOW;
    }
    return VIRT_DRTM_EVENT_LOG_OK;
}

static uint16_t digest_size(uint16_t algorithm)
{
    switch (algorithm) {
    case VIRT_DRTM_TPM_ALG_SHA1:
        return 20;
    case VIRT_DRTM_TPM_ALG_SHA256:
        return 32;
    case VIRT_DRTM_TPM_ALG_SHA384:
        return 48;
    case VIRT_DRTM_TPM_ALG_SHA512:
        return 64;
    default:
        g_assert_not_reached();
    }
}

static void write_spec_id(EventWriter *w,
                          const VirtDRTMMeasurementManifest *manifest)
{
    static const uint8_t signature[16] = "Spec ID Event03";
    size_t bank_count = virt_drtm_measurement_manifest_bank_count(manifest);
    size_t event_size = SPEC_FIXED_SIZE + 4 * bank_count;
    uint8_t *p = w->output;
    size_t i;

    stl_le_p(p, 0);
    stl_le_p(p + 4, EV_NO_ACTION);
    memset(p + 8, 0, 20);
    stl_le_p(p + 28, event_size);
    memcpy(p + 32, signature, sizeof(signature));
    stl_le_p(p + 48, 0);       /* platformClass */
    p[52] = 0;                 /* specVersionMinor */
    p[53] = 2;                 /* specVersionMajor */
    p[54] = 2;                 /* specErrata */
    p[55] = 2;                 /* UINTN is 64 bits */
    stl_le_p(p + 56, bank_count);
    p += 60;
    for (i = 0; i < bank_count; i++) {
        uint16_t algorithm = virt_drtm_measurement_manifest_bank(manifest, i);

        stw_le_p(p, algorithm);
        stw_le_p(p + 2, digest_size(algorithm));
        p += 4;
    }
    *p = 0;                    /* vendorInfoSize */
    w->offset = LEGACY_HEADER_SIZE + event_size;
}

static void write_event(EventWriter *w,
                        const VirtDRTMMeasurementEvent *event)
{
    uint8_t *p = w->output + w->offset;
    size_t i;

    stl_le_p(p, event->pcr);
    stl_le_p(p + 4, event->type);
    stl_le_p(p + 8, event->digest_count);
    p += 12;
    for (i = 0; i < event->digest_count; i++) {
        stw_le_p(p, event->digests[i].algorithm);
        memcpy(p + 2, event->digests[i].value, event->digests[i].size);
        p += 2 + event->digests[i].size;
    }
    stl_le_p(p, event->event_data.size);
    p += 4;
    if (event->event_data.size) {
        memcpy(p, event->event_data.data, event->event_data.size);
        p += event->event_data.size;
    }
    w->offset = p - w->output;
}

VirtDRTMEventLogStatus virt_drtm_event_log_build(
    const VirtDRTMEventLogInput *input, uint8_t *output, size_t output_size,
    size_t *required_size)
{
    VirtDRTMMeasurementManifest *manifest;
    EventWriter w = { .output = output };
    VirtDRTMEventLogStatus status;
    size_t bank_count, event_count, total, i;

    if (!required_size) {
        return VIRT_DRTM_EVENT_LOG_INVALID;
    }
    status = virt_drtm_measurement_manifest_build(input, &manifest);
    if (status != VIRT_DRTM_EVENT_LOG_OK) {
        return status;
    }
    bank_count = virt_drtm_measurement_manifest_bank_count(manifest);
    event_count = virt_drtm_measurement_manifest_event_count(manifest);
    total = LEGACY_HEADER_SIZE + SPEC_FIXED_SIZE;
    if (bank_count > (SIZE_MAX - total) / 4) {
        status = VIRT_DRTM_EVENT_LOG_OVERFLOW;
        goto out;
    }
    total += 4 * bank_count;
    for (i = 0; i < event_count; i++) {
        status = event_size(virt_drtm_measurement_manifest_event(manifest, i),
                            &total);
        if (status != VIRT_DRTM_EVENT_LOG_OK) {
            goto out;
        }
    }
    *required_size = total;
    if (!output) {
        status = VIRT_DRTM_EVENT_LOG_OK;
        goto out;
    }
    if (output_size < total) {
        status = VIRT_DRTM_EVENT_LOG_TOO_SMALL;
        goto out;
    }
    write_spec_id(&w, manifest);
    for (i = 0; i < event_count; i++) {
        write_event(&w,
                    virt_drtm_measurement_manifest_event(manifest, i));
    }
    assert(w.offset == total);
    status = VIRT_DRTM_EVENT_LOG_OK;
out:
    virt_drtm_measurement_manifest_free(manifest);
    return status;
}
