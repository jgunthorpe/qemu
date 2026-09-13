/*
 * Arm DRTM firmware measurement manifest
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "crypto/hash.h"
#include "hw/arm/virt-drtm-measurement.h"
#include "qemu/bswap.h"

typedef struct ManifestEvent {
    VirtDRTMMeasurementEvent public;
    VirtDRTMDigest digests[VIRT_DRTM_MAX_PCR_BANKS];
    uint8_t inline_data[2 + VIRT_DRTM_MAX_DIGEST_SIZE];
    uint8_t *owned_data;
    bool dce_owned;
} ManifestEvent;

struct VirtDRTMMeasurementManifest {
    uint16_t selected_algorithm;
    uint16_t banks[VIRT_DRTM_MAX_PCR_BANKS];
    size_t bank_count;
    ManifestEvent *events;
    size_t event_count;
    VirtDRTMMeasurementOperation *operations;
    size_t operation_count;
    size_t dce_operation;
};

static bool blob_valid(VirtDRTMBlob blob)
{
    return !blob.size || blob.data;
}

static bool event_data_valid(VirtDRTMBlob blob)
{
    return blob.size <= UINT32_MAX && blob_valid(blob);
}

static bool algorithm_info(uint16_t algorithm, QCryptoHashAlgo *qalgorithm,
                           uint16_t *digest_size)
{
    switch (algorithm) {
    case VIRT_DRTM_TPM_ALG_SHA1:
        *qalgorithm = QCRYPTO_HASH_ALGO_SHA1;
        *digest_size = 20;
        return true;
    case VIRT_DRTM_TPM_ALG_SHA256:
        *qalgorithm = QCRYPTO_HASH_ALGO_SHA256;
        *digest_size = 32;
        return true;
    case VIRT_DRTM_TPM_ALG_SHA384:
        *qalgorithm = QCRYPTO_HASH_ALGO_SHA384;
        *digest_size = 48;
        return true;
    case VIRT_DRTM_TPM_ALG_SHA512:
        *qalgorithm = QCRYPTO_HASH_ALGO_SHA512;
        *digest_size = 64;
        return true;
    default:
        return false;
    }
}

static VirtDRTMEventLogStatus digest_bytes(uint16_t algorithm,
                                           const uint8_t *data, size_t size,
                                           VirtDRTMDigest *digest)
{
    QCryptoHashAlgo qalgorithm;
    uint8_t *result = digest->value;
    uint16_t digest_size;
    size_t result_size;

    if (!algorithm_info(algorithm, &qalgorithm, &digest_size)) {
        return VIRT_DRTM_EVENT_LOG_INVALID;
    }
    digest->algorithm = algorithm;
    digest->size = digest_size;
    result_size = digest_size;
    if (qcrypto_hash_bytes(qalgorithm, data, size, &result, &result_size,
                           NULL) < 0 || result != digest->value ||
        result_size != digest_size) {
        return VIRT_DRTM_EVENT_LOG_HASH_ERROR;
    }
    return VIRT_DRTM_EVENT_LOG_OK;
}

VirtDRTMEventLogStatus virt_drtm_firmware_hash_select(
    const uint16_t *active_banks, size_t active_bank_count,
    uint16_t *selected_algorithm)
{
    bool sha256 = false, sha384 = false, sha512 = false;
    size_t i, j;
    QCryptoHashAlgo unused_algorithm;
    uint16_t unused_size;

    if (!active_banks || !active_bank_count || !selected_algorithm ||
        active_bank_count > VIRT_DRTM_MAX_PCR_BANKS) {
        return VIRT_DRTM_EVENT_LOG_INVALID;
    }
    for (i = 0; i < active_bank_count; i++) {
        if (!algorithm_info(active_banks[i], &unused_algorithm,
                            &unused_size)) {
            return VIRT_DRTM_EVENT_LOG_INVALID;
        }
        for (j = 0; j < i; j++) {
            if (active_banks[j] == active_banks[i]) {
                return VIRT_DRTM_EVENT_LOG_INVALID;
            }
        }
        sha256 |= active_banks[i] == VIRT_DRTM_TPM_ALG_SHA256;
        sha384 |= active_banks[i] == VIRT_DRTM_TPM_ALG_SHA384;
        sha512 |= active_banks[i] == VIRT_DRTM_TPM_ALG_SHA512;
    }
    /* R48000 prefers SHA-384 when available, then a stronger algorithm. */
    *selected_algorithm = sha384 ? VIRT_DRTM_TPM_ALG_SHA384 :
                          sha512 ? VIRT_DRTM_TPM_ALG_SHA512 :
                                   VIRT_DRTM_TPM_ALG_SHA256;
    if (!sha256 && !sha384 && !sha512) {
        return VIRT_DRTM_EVENT_LOG_INVALID;
    }
    return VIRT_DRTM_EVENT_LOG_OK;
}

static int compare_u16(const void *a, const void *b)
{
    uint16_t av = *(const uint16_t *)a;
    uint16_t bv = *(const uint16_t *)b;

    return (av > bv) - (av < bv);
}

static VirtDRTMEventLogStatus add_event(
    VirtDRTMMeasurementManifest *m, uint32_t pcr, uint32_t type,
    const uint8_t *measured, size_t measured_size, VirtDRTMBlob event_data,
    bool dce_owned)
{
    ManifestEvent *event = &m->events[m->event_count];
    VirtDRTMEventLogStatus status;

    event->public.pcr = pcr;
    event->public.type = type;
    event->public.digests = event->digests;
    event->public.digest_count = 1;
    event->dce_owned = dce_owned;
    if (event_data.size) {
        event->owned_data = g_try_malloc(event_data.size);
        if (!event->owned_data) {
            return VIRT_DRTM_EVENT_LOG_OVERFLOW;
        }
        memcpy(event->owned_data, event_data.data, event_data.size);
        event->public.event_data = (VirtDRTMBlob) {
            event->owned_data, event_data.size
        };
    }
    status = digest_bytes(m->selected_algorithm, measured, measured_size,
                          &event->digests[0]);
    if (status != VIRT_DRTM_EVENT_LOG_OK) {
        g_free(event->owned_data);
        event->owned_data = NULL;
        return status;
    }
    m->event_count++;
    return VIRT_DRTM_EVENT_LOG_OK;
}

static VirtDRTMEventLogStatus add_inline_event(
    VirtDRTMMeasurementManifest *m, uint32_t pcr, uint32_t type,
    const uint8_t *measured, size_t measured_size,
    const uint8_t *event_data, size_t event_data_size, bool dce_owned)
{
    return add_event(m, pcr, type, measured, measured_size,
                     (VirtDRTMBlob) { event_data, event_data_size },
                     dce_owned);
}

static void append_event_operations(VirtDRTMMeasurementManifest *m,
                                    bool dce_owned)
{
    size_t i;

    /* Event zero is represented by the locality-4 HASH sequence. */
    for (i = 1; i < m->event_count; i++) {
        ManifestEvent *event = &m->events[i];
        VirtDRTMMeasurementOperation *operation;

        if (event->dce_owned != dce_owned) {
            continue;
        }
        operation = &m->operations[m->operation_count++];
        operation->type = VIRT_DRTM_MEASUREMENT_PCR_EXTEND;
        operation->pcr = event->public.pcr;
        operation->digest = event->digests[0];
    }
}

static VirtDRTMEventLogStatus add_dce(VirtDRTMMeasurementManifest *m,
                                      VirtDRTMBlob image)
{
    uint8_t zero = 0;
    ManifestEvent *event = &m->events[m->event_count++];
    VirtDRTMMeasurementOperation *operation;
    VirtDRTMDigest dce_digest;
    VirtDRTMEventLogStatus status;
    size_t i;

    if (!image.size) {
        image = (VirtDRTMBlob) { &zero, 1 };
    }
    status = digest_bytes(m->selected_algorithm, image.data, image.size,
                          &dce_digest);
    if (status != VIRT_DRTM_EVENT_LOG_OK) {
        return status;
    }
    event->public.pcr = 17;
    event->public.type = VIRT_DRTM_EV_DCE;
    event->public.digests = event->digests;
    event->public.digest_count = m->bank_count;
    stw_le_p(event->inline_data, dce_digest.algorithm);
    memcpy(event->inline_data + 2, dce_digest.value, dce_digest.size);
    event->public.event_data = (VirtDRTMBlob) {
        event->inline_data, 2 + dce_digest.size
    };
    for (i = 0; i < m->bank_count; i++) {
        status = digest_bytes(m->banks[i], dce_digest.value, dce_digest.size,
                              &event->digests[i]);
        if (status != VIRT_DRTM_EVENT_LOG_OK) {
            return status;
        }
    }
    m->operations[m->operation_count++].type =
        VIRT_DRTM_MEASUREMENT_HASH_START;
    operation = &m->operations[m->operation_count++];
    operation->type = VIRT_DRTM_MEASUREMENT_HASH_DATA;
    operation->pcr = 17;
    operation->digest = dce_digest;
    m->operations[m->operation_count++].type =
        VIRT_DRTM_MEASUREMENT_HASH_END;
    return VIRT_DRTM_EVENT_LOG_OK;
}

static bool validate_input(const VirtDRTMEventLogInput *input)
{
    size_t i;

    if (!input || input->pcr_schema_value != 0x01 ||
        !blob_valid(input->dce_image) ||
        !blob_valid(input->dce_public_key) ||
        !event_data_valid(input->dce_certificate_chain) ||
        !blob_valid(input->dlme_image) || !input->dlme_image.size ||
        (input->tzfw_count && !input->tzfw)) {
        return false;
    }
    if ((!input->dce_image.size &&
         (input->dce_public_key.size || input->dce_certificate_chain.size)) ||
        (input->dce_image.size && !input->dce_public_key.size)) {
        return false;
    }
    for (i = 0; i < input->tzfw_count; i++) {
        if (!blob_valid(input->tzfw[i].image) ||
            !input->tzfw[i].image.size ||
            !event_data_valid(input->tzfw[i].event_data)) {
            return false;
        }
    }
    return true;
}

VirtDRTMEventLogStatus virt_drtm_measurement_manifest_build(
    const VirtDRTMEventLogInput *input, VirtDRTMMeasurementManifest **result)
{
    static const uint8_t separator[] = "ARM_DRTM";
    uint8_t schema, one = 1, debug, lifecycle, entry[8], zero = 0;
    VirtDRTMMeasurementManifest *m;
    VirtDRTMEventLogStatus status;
    size_t max_events, max_operations, i;

    if (!result) {
        return VIRT_DRTM_EVENT_LOG_INVALID;
    }
    *result = NULL;
    if (!validate_input(input)) {
        return VIRT_DRTM_EVENT_LOG_INVALID;
    }
    if (input->tzfw_count > SIZE_MAX - 11) {
        return VIRT_DRTM_EVENT_LOG_OVERFLOW;
    }
    max_events = 10 + input->tzfw_count + input->secure_interrupts_disabled;
    m = g_try_new0(VirtDRTMMeasurementManifest, 1);
    if (!m) {
        return VIRT_DRTM_EVENT_LOG_OVERFLOW;
    }
    status = virt_drtm_firmware_hash_select(input->active_banks,
                                             input->active_bank_count,
                                             &m->selected_algorithm);
    if (status != VIRT_DRTM_EVENT_LOG_OK) {
        goto fail;
    }
    m->bank_count = input->active_bank_count;
    memcpy(m->banks, input->active_banks,
           m->bank_count * sizeof(m->banks[0]));
    qsort(m->banks, m->bank_count, sizeof(m->banks[0]), compare_u16);
    if (max_events > SIZE_MAX - 2 - 2 * (m->bank_count - 1)) {
        status = VIRT_DRTM_EVENT_LOG_OVERFLOW;
        goto fail;
    }
    max_operations = 2 + 2 * (m->bank_count - 1) + max_events;
    m->events = g_try_new0(ManifestEvent, max_events);
    m->operations = g_try_new0(VirtDRTMMeasurementOperation, max_operations);
    if (!m->events || !m->operations) {
        status = VIRT_DRTM_EVENT_LOG_OVERFLOW;
        goto fail;
    }
    status = add_dce(m, input->dce_image);
    if (status != VIRT_DRTM_EVENT_LOG_OK) {
        goto fail;
    }
    /* R44210/R62175 cap each active bank not selected for firmware extends. */
    for (i = 0; i < m->bank_count; i++) {
        unsigned int pcr;

        if (m->banks[i] == m->selected_algorithm) {
            continue;
        }
        for (pcr = 17; pcr <= 18; pcr++) {
            VirtDRTMMeasurementOperation *op =
                &m->operations[m->operation_count++];
            QCryptoHashAlgo unused_algorithm;

            op->type = VIRT_DRTM_MEASUREMENT_PCR_CAP;
            op->pcr = pcr;
            algorithm_info(m->banks[i], &unused_algorithm, &op->digest.size);
            op->digest.algorithm = m->banks[i];
        }
    }

#define ADD(owner, pcr, type, bytes, bytes_size, payload) do {             \
        status = add_event(m, (pcr), (type), (bytes), (bytes_size),        \
                           (payload), (owner));                            \
        if (status != VIRT_DRTM_EVENT_LOG_OK) {                            \
            goto fail;                                                     \
        }                                                                  \
    } while (0)
#define ADD_INLINE(owner, pcr, type, bytes, bytes_size, data, data_size) do { \
        status = add_inline_event(m, (pcr), (type), (bytes), (bytes_size), \
                                  (data), (data_size), (owner));           \
        if (status != VIRT_DRTM_EVENT_LOG_OK) {                            \
            goto fail;                                                     \
        }                                                                  \
    } while (0)
    schema = input->pcr_schema_value;
    debug = input->debug_or_trace_enabled;
    lifecycle = input->nonsecure_lifecycle;
    stq_le_p(entry, input->dlme_entry_point_offset);
    ADD_INLINE(false, 17, VIRT_DRTM_EV_PCR_SCHEMA, &schema, 1, &schema, 1);
    for (i = 0; i < input->tzfw_count; i++) {
        ADD(false, 17, VIRT_DRTM_EV_TZFW, input->tzfw[i].image.data,
            input->tzfw[i].image.size, input->tzfw[i].event_data);
    }
    if (input->secure_interrupts_disabled) {
        ADD_INLINE(false, 17, VIRT_DRTM_EV_SECURE_INT_DISABLE, &one, 1,
                   &one, 1);
    }
    ADD_INLINE(true, 17, VIRT_DRTM_EV_SEPARATOR, separator,
               sizeof(separator) - 1, separator, sizeof(separator) - 1);
    ADD_INLINE(false, 18, VIRT_DRTM_EV_PCR_SCHEMA, &schema, 1, &schema, 1);
    if (input->dce_image.size) {
        ADD(false, 18, VIRT_DRTM_EV_DCE_PUBKEY, input->dce_public_key.data,
            input->dce_public_key.size, input->dce_certificate_chain);
    } else {
        ADD(false, 18, VIRT_DRTM_EV_DCE_PUBKEY, &zero, 1,
            ((VirtDRTMBlob) { 0 }));
    }
    ADD_INLINE(false, 18, VIRT_DRTM_EV_DEBUG_CONFIG, &debug, 1, &debug, 1);
    ADD_INLINE(false, 18, VIRT_DRTM_EV_NONSECURE_CONFIG, &lifecycle, 1,
               &lifecycle, 1);
    ADD(true, 18, VIRT_DRTM_EV_DLME, input->dlme_image.data,
        input->dlme_image.size, ((VirtDRTMBlob) { 0 }));
    ADD_INLINE(true, 18, VIRT_DRTM_EV_DLME_ENTRY_POINT, entry, sizeof(entry),
               entry, sizeof(entry));
    ADD_INLINE(true, 18, VIRT_DRTM_EV_SEPARATOR, separator,
               sizeof(separator) - 1,
               separator, sizeof(separator) - 1);
#undef ADD_INLINE
#undef ADD
    /* Stable phase partition; event-log serialization remains PCR ordered. */
    append_event_operations(m, false);
    m->dce_operation = m->operation_count;
    append_event_operations(m, true);
    *result = m;
    return VIRT_DRTM_EVENT_LOG_OK;

fail:
    virt_drtm_measurement_manifest_free(m);
    return status;
}

void virt_drtm_measurement_manifest_free(VirtDRTMMeasurementManifest *m)
{
    if (m) {
        size_t i;

        for (i = 0; i < m->event_count; i++) {
            g_free(m->events[i].owned_data);
        }
        g_free(m->operations);
        g_free(m->events);
        g_free(m);
    }
}

uint16_t virt_drtm_measurement_manifest_algorithm(
    const VirtDRTMMeasurementManifest *m)
{
    return m->selected_algorithm;
}

size_t virt_drtm_measurement_manifest_bank_count(
    const VirtDRTMMeasurementManifest *m)
{
    return m->bank_count;
}

uint16_t virt_drtm_measurement_manifest_bank(
    const VirtDRTMMeasurementManifest *m, size_t index)
{
    g_assert(index < m->bank_count);
    return m->banks[index];
}

size_t virt_drtm_measurement_manifest_event_count(
    const VirtDRTMMeasurementManifest *m)
{
    return m->event_count;
}

const VirtDRTMMeasurementEvent *virt_drtm_measurement_manifest_event(
    const VirtDRTMMeasurementManifest *m, size_t index)
{
    g_assert(index < m->event_count);
    return &m->events[index].public;
}

size_t virt_drtm_measurement_manifest_operation_count(
    const VirtDRTMMeasurementManifest *m)
{
    return m->operation_count;
}

size_t virt_drtm_measurement_manifest_dce_operation(
    const VirtDRTMMeasurementManifest *m)
{
    return m->dce_operation;
}

const VirtDRTMMeasurementOperation *virt_drtm_measurement_manifest_operation(
    const VirtDRTMMeasurementManifest *m, size_t index)
{
    g_assert(index < m->operation_count);
    return &m->operations[index];
}
