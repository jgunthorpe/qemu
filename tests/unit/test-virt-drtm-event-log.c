/*
 * Arm DRTM crypto-agile event log serializer tests
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "crypto/hash.h"
#include "crypto/init.h"
#include "hw/arm/virt-drtm-event-log.h"
#include "hw/arm/virt-drtm-measurement.h"
#include "qemu/bswap.h"
#include "qemu/cutils.h"

typedef struct ParsedEvent {
    uint32_t pcr;
    uint32_t type;
    uint32_t digest_count;
    uint16_t algorithm;
    const uint8_t *digest;
    size_t digest_size;
    uint16_t algorithms[VIRT_DRTM_MAX_PCR_BANKS];
    const uint8_t *digests[VIRT_DRTM_MAX_PCR_BANKS];
    size_t digest_sizes[VIRT_DRTM_MAX_PCR_BANKS];
    const uint8_t *data;
    uint32_t data_size;
} ParsedEvent;

typedef struct Fixture {
    uint8_t dlme[19];
    uint16_t banks[VIRT_DRTM_MAX_PCR_BANKS];
    VirtDRTMEventLogInput input;
} Fixture;

static size_t digest_size(uint16_t algorithm)
{
    switch (algorithm) {
    case 4:
        return 20;
    case 0xb:
        return 32;
    case 0xc:
        return 48;
    case 0xd:
        return 64;
    default:
        g_assert_not_reached();
    }
}

static void fixture_init(Fixture *f, uint16_t algorithm)
{
    size_t i;

    memset(f, 0, sizeof(*f));
    for (i = 0; i < sizeof(f->dlme); i++) {
        f->dlme[i] = 0x40 + i;
    }
    f->banks[0] = algorithm;
    f->input = (VirtDRTMEventLogInput) {
        .active_banks = f->banks,
        .active_bank_count = 1,
        .pcr_schema_value = 1,
        .debug_or_trace_enabled = true,
        .nonsecure_lifecycle = false,
        .dlme_image = { f->dlme, sizeof(f->dlme) },
        .dlme_entry_point_offset = UINT64_C(0x8877665544332211),
    };
}

static uint8_t *build(Fixture *f, size_t *size)
{
    uint8_t *log;

    g_assert_cmpint(virt_drtm_event_log_build(&f->input, NULL, 0, size), ==,
                    VIRT_DRTM_EVENT_LOG_OK);
    log = g_malloc(*size);
    g_assert_cmpint(virt_drtm_event_log_build(&f->input, log, *size, size), ==,
                    VIRT_DRTM_EVENT_LOG_OK);
    return log;
}

static size_t parse_event(const uint8_t *log, size_t log_size, size_t offset,
                          ParsedEvent *event)
{
    const uint8_t *p;
    size_t i, size;

    g_assert_cmpuint(log_size - offset, >=, 16);
    event->pcr = ldl_le_p(log + offset);
    event->type = ldl_le_p(log + offset + 4);
    event->digest_count = ldl_le_p(log + offset + 8);
    g_assert_cmpuint(event->digest_count, >, 0);
    g_assert_cmpuint(event->digest_count, <=, VIRT_DRTM_MAX_PCR_BANKS);
    p = log + offset + 12;
    for (i = 0; i < event->digest_count; i++) {
        g_assert_cmpuint(log + log_size - p, >=, 2);
        event->algorithms[i] = lduw_le_p(p);
        event->digest_sizes[i] = digest_size(event->algorithms[i]);
        event->digests[i] = p + 2;
        g_assert_cmpuint(log + log_size - p, >=,
                         2 + event->digest_sizes[i]);
        p += 2 + event->digest_sizes[i];
    }
    event->algorithm = event->algorithms[0];
    event->digest_size = event->digest_sizes[0];
    event->digest = event->digests[0];
    g_assert_cmpuint(log + log_size - p, >=, 4);
    event->data_size = ldl_le_p(p);
    event->data = p + 4;
    size = event->data + event->data_size - (log + offset);
    g_assert_cmpuint(log_size - offset, >=, size);
    return offset + size;
}

static void expect_hash(uint16_t algorithm, const uint8_t *bytes, size_t size,
                        const uint8_t *actual)
{
    QCryptoHashAlgo qalgorithm = algorithm == 4 ? QCRYPTO_HASH_ALGO_SHA1 :
                                algorithm == 0xb ? QCRYPTO_HASH_ALGO_SHA256 :
                                algorithm == 0xc ? QCRYPTO_HASH_ALGO_SHA384 :
                                                   QCRYPTO_HASH_ALGO_SHA512;
    uint8_t expected[64], *result = expected;
    size_t expected_size = digest_size(algorithm);

    g_assert_cmpint(qcrypto_hash_bytes(qalgorithm, bytes, size, &result,
                                       &expected_size, &error_abort), ==, 0);
    g_assert_true(result == expected);
    g_assert_cmpmem(actual, expected_size, expected, expected_size);
}

static size_t check_event(const uint8_t *log, size_t log_size, size_t offset,
                          uint32_t pcr, uint32_t type, const uint8_t *measured,
                          size_t measured_size, const uint8_t *data,
                          size_t data_size)
{
    ParsedEvent event;

    offset = parse_event(log, log_size, offset, &event);
    g_assert_cmpuint(event.digest_count, ==, 1);
    g_assert_cmpuint(event.pcr, ==, pcr);
    g_assert_cmphex(event.type, ==, type);
    expect_hash(event.algorithm, measured, measured_size, event.digest);
    g_assert_cmpuint(event.data_size, ==, data_size);
    if (data_size) {
        g_assert_cmpmem(event.data, data_size, data, data_size);
    }
    return offset;
}

static void check_spec(const uint8_t *log, uint16_t algorithm)
{
    static const uint8_t signature[16] = "Spec ID Event03";

    g_assert_cmpuint(ldl_le_p(log), ==, 0);
    g_assert_cmpuint(ldl_le_p(log + 4), ==, 3);
    g_assert_true(buffer_is_zero(log + 8, 20));
    g_assert_cmpuint(ldl_le_p(log + 28), ==, 33);
    g_assert_cmpmem(log + 32, 16, signature, 16);
    g_assert_cmpuint(ldl_le_p(log + 48), ==, 0);
    g_assert_cmpuint(log[52], ==, 0);
    g_assert_cmpuint(log[53], ==, 2);
    g_assert_cmpuint(log[54], ==, 2);
    g_assert_cmpuint(log[55], ==, 2);
    g_assert_cmpuint(ldl_le_p(log + 56), ==, 1);
    g_assert_cmpuint(lduw_le_p(log + 60), ==, algorithm);
    g_assert_cmpuint(lduw_le_p(log + 62), ==, digest_size(algorithm));
    g_assert_cmpuint(log[64], ==, 0);
}

static void hash_digest(uint16_t algorithm, const uint8_t *bytes, size_t size,
                        uint8_t *digest)
{
    QCryptoHashAlgo qalgorithm = algorithm == 4 ? QCRYPTO_HASH_ALGO_SHA1 :
                                algorithm == 0xb ? QCRYPTO_HASH_ALGO_SHA256 :
                                algorithm == 0xc ? QCRYPTO_HASH_ALGO_SHA384 :
                                                   QCRYPTO_HASH_ALGO_SHA512;
    uint8_t *result = digest;
    size_t result_size = digest_size(algorithm);

    g_assert_cmpint(qcrypto_hash_bytes(qalgorithm, bytes, size, &result,
                                       &result_size, &error_abort), ==, 0);
    g_assert_true(result == digest);
}

static void test_sha1_active_sha256_selected(void)
{
    uint16_t banks[] = { 0xb, 4 };
    VirtDRTMMeasurementManifest *manifest;
    const VirtDRTMMeasurementEvent *event;
    const VirtDRTMMeasurementOperation *operation;
    Fixture f;
    ParsedEvent parsed;
    uint8_t *log;
    size_t size, offset;

    fixture_init(&f, 0xb);
    memcpy(f.banks, banks, sizeof(banks));
    f.input.active_bank_count = ARRAY_SIZE(banks);
    g_assert_cmpint(virt_drtm_measurement_manifest_build(&f.input, &manifest),
                    ==, VIRT_DRTM_EVENT_LOG_OK);
    g_assert_cmphex(virt_drtm_measurement_manifest_algorithm(manifest), ==,
                    VIRT_DRTM_TPM_ALG_SHA256);
    event = virt_drtm_measurement_manifest_event(manifest, 0);
    g_assert_cmpuint(event->digest_count, ==, 2);
    g_assert_cmphex(event->digests[0].algorithm, ==,
                    VIRT_DRTM_TPM_ALG_SHA1);
    g_assert_cmphex(event->digests[1].algorithm, ==,
                    VIRT_DRTM_TPM_ALG_SHA256);
    operation = virt_drtm_measurement_manifest_operation(manifest, 3);
    g_assert_cmpint(operation->type, ==, VIRT_DRTM_MEASUREMENT_PCR_CAP);
    g_assert_cmpuint(operation->pcr, ==, 17);
    g_assert_cmphex(operation->digest.algorithm, ==,
                    VIRT_DRTM_TPM_ALG_SHA1);
    operation = virt_drtm_measurement_manifest_operation(manifest, 4);
    g_assert_cmpint(operation->type, ==, VIRT_DRTM_MEASUREMENT_PCR_CAP);
    g_assert_cmpuint(operation->pcr, ==, 18);
    g_assert_cmphex(operation->digest.algorithm, ==,
                    VIRT_DRTM_TPM_ALG_SHA1);

    log = build(&f, &size);
    g_assert_cmpuint(ldl_le_p(log + 56), ==, 2);
    g_assert_cmphex(lduw_le_p(log + 60), ==, VIRT_DRTM_TPM_ALG_SHA1);
    g_assert_cmphex(lduw_le_p(log + 64), ==, VIRT_DRTM_TPM_ALG_SHA256);
    offset = parse_event(log, size, 69, &parsed);
    g_assert_cmpuint(parsed.digest_count, ==, 2);
    g_assert_cmphex(parsed.algorithms[0], ==, VIRT_DRTM_TPM_ALG_SHA1);
    g_assert_cmphex(parsed.algorithms[1], ==, VIRT_DRTM_TPM_ALG_SHA256);
    g_assert_cmpuint(offset, <, size);
    g_free(log);
    virt_drtm_measurement_manifest_free(manifest);
}

static void test_multibank_manifest_and_replay(void)
{
    static const uint16_t expected_banks[] = { 4, 0xb, 0xc, 0xd };
    uint16_t banks[] = { 0xd, 0xb, 4, 0xc };
    uint8_t zero = 0, dce_digest[64], concatenated[128];
    uint8_t pcrs[VIRT_DRTM_MAX_PCR_BANKS][2][64] = { 0 };
    bool replayed_events[32] = { false };
    VirtDRTMMeasurementManifest *manifest;
    const VirtDRTMMeasurementEvent *manifest_event;
    const VirtDRTMMeasurementOperation *operation;
    ParsedEvent parsed;
    Fixture f;
    Fixture reordered;
    uint8_t *log, *second_log;
    size_t size, second_size, offset, i, j, replayed_event_count = 1;
    size_t dce_operation;

    fixture_init(&f, 0xb);
    memcpy(f.banks, banks, sizeof(banks));
    f.input.active_bank_count = ARRAY_SIZE(banks);
    g_assert_cmpint(virt_drtm_measurement_manifest_build(&f.input, &manifest),
                    ==, VIRT_DRTM_EVENT_LOG_OK);
    g_assert_cmphex(virt_drtm_measurement_manifest_algorithm(manifest), ==,
                    VIRT_DRTM_TPM_ALG_SHA384);
    g_assert_cmpuint(virt_drtm_measurement_manifest_bank_count(manifest), ==,
                     ARRAY_SIZE(expected_banks));
    for (i = 0; i < ARRAY_SIZE(expected_banks); i++) {
        g_assert_cmphex(virt_drtm_measurement_manifest_bank(manifest, i), ==,
                        expected_banks[i]);
    }

    manifest_event = virt_drtm_measurement_manifest_event(manifest, 0);
    g_assert_cmpuint(manifest_event->digest_count, ==, 4);
    hash_digest(0xc, &zero, 1, dce_digest);
    for (i = 0; i < ARRAY_SIZE(expected_banks); i++) {
        uint8_t expected[64];

        hash_digest(expected_banks[i], dce_digest, 48, expected);
        g_assert_cmphex(manifest_event->digests[i].algorithm, ==,
                        expected_banks[i]);
        g_assert_cmpmem(manifest_event->digests[i].value,
                        manifest_event->digests[i].size,
                        expected, digest_size(expected_banks[i]));
    }
    g_assert_cmphex(lduw_le_p(manifest_event->event_data.data), ==, 0xc);
    g_assert_cmpmem(manifest_event->event_data.data + 2, 48, dce_digest, 48);

    g_assert_cmpuint(virt_drtm_measurement_manifest_operation_count(manifest),
                     ==, 18);
    g_assert_cmpuint(virt_drtm_measurement_manifest_event_count(manifest),
                     <=, ARRAY_SIZE(replayed_events));
    replayed_events[0] = true;
    operation = virt_drtm_measurement_manifest_operation(manifest, 0);
    g_assert_cmpint(operation->type, ==, VIRT_DRTM_MEASUREMENT_HASH_START);
    operation = virt_drtm_measurement_manifest_operation(manifest, 1);
    g_assert_cmpint(operation->type, ==, VIRT_DRTM_MEASUREMENT_HASH_DATA);
    g_assert_cmphex(operation->digest.algorithm, ==, 0xc);
    g_assert_cmpmem(operation->digest.value, 48, dce_digest, 48);
    operation = virt_drtm_measurement_manifest_operation(manifest, 2);
    g_assert_cmpint(operation->type, ==, VIRT_DRTM_MEASUREMENT_HASH_END);
    for (i = 3; i < 9; i++) {
        static const uint16_t cap_banks[] = { 4, 4, 0xb, 0xb, 0xd, 0xd };
        static const uint32_t cap_pcrs[] = { 17, 18, 17, 18, 17, 18 };

        operation = virt_drtm_measurement_manifest_operation(manifest, i);
        g_assert_cmpint(operation->type, ==, VIRT_DRTM_MEASUREMENT_PCR_CAP);
        g_assert_cmphex(operation->digest.algorithm, ==, cap_banks[i - 3]);
        g_assert_cmpuint(operation->pcr, ==, cap_pcrs[i - 3]);
        g_assert_true(buffer_is_zero(operation->digest.value,
                                     operation->digest.size));
    }

    /* R45300: PCR17's separator is the first DCE-owned TPM operation. */
    dce_operation = virt_drtm_measurement_manifest_dce_operation(manifest);
    manifest_event = virt_drtm_measurement_manifest_event(manifest, 2);
    operation = virt_drtm_measurement_manifest_operation(manifest,
                                                          dce_operation);
    g_assert_cmphex(manifest_event->type, ==, VIRT_DRTM_EV_SEPARATOR);
    g_assert_cmpuint(manifest_event->pcr, ==, 17);
    g_assert_cmpint(operation->type, ==, VIRT_DRTM_MEASUREMENT_PCR_EXTEND);
    g_assert_cmpuint(operation->pcr, ==, manifest_event->pcr);
    g_assert_cmpmem(operation->digest.value, operation->digest.size,
                    manifest_event->digests[0].value,
                    manifest_event->digests[0].size);

    /* Replay HASH_END, caps, and ordinary extends into each active bank. */
    for (i = 0; i < ARRAY_SIZE(expected_banks); i++) {
        size_t dsize = digest_size(expected_banks[i]);

        memset(concatenated, 0, dsize);
        memcpy(concatenated + dsize, manifest_event->digests[i].value, dsize);
        hash_digest(expected_banks[i], concatenated, 2 * dsize, pcrs[i][0]);
    }
    for (i = 3;
         i < virt_drtm_measurement_manifest_operation_count(manifest); i++) {
        operation = virt_drtm_measurement_manifest_operation(manifest, i);
        if (operation->type == VIRT_DRTM_MEASUREMENT_PCR_CAP ||
            operation->type == VIRT_DRTM_MEASUREMENT_PCR_EXTEND) {
            size_t bank, pcr = operation->pcr - 17;
            size_t dsize = operation->digest.size;

            for (bank = 0; bank < ARRAY_SIZE(expected_banks); bank++) {
                if (expected_banks[bank] == operation->digest.algorithm) {
                    break;
                }
            }
            g_assert_cmpuint(bank, <, ARRAY_SIZE(expected_banks));
            memcpy(concatenated, pcrs[bank][pcr], dsize);
            memcpy(concatenated + dsize, operation->digest.value, dsize);
            hash_digest(operation->digest.algorithm, concatenated, 2 * dsize,
                        pcrs[bank][pcr]);
            if (operation->type == VIRT_DRTM_MEASUREMENT_PCR_EXTEND) {
                for (j = 1;
                     j < virt_drtm_measurement_manifest_event_count(manifest);
                     j++) {
                    manifest_event = virt_drtm_measurement_manifest_event(
                        manifest, j);
                    if (!replayed_events[j] &&
                        manifest_event->pcr == operation->pcr &&
                        manifest_event->digest_count == 1 &&
                        manifest_event->digests[0].size == dsize &&
                        !memcmp(manifest_event->digests[0].value,
                                operation->digest.value, dsize)) {
                        replayed_events[j] = true;
                        replayed_event_count++;
                        break;
                    }
                }
                g_assert_cmpuint(j, <,
                    virt_drtm_measurement_manifest_event_count(manifest));
            }
        }
    }
    g_assert_cmpuint(replayed_event_count, ==,
                     virt_drtm_measurement_manifest_event_count(manifest));

    log = build(&f, &size);
    g_assert_cmpuint(ldl_le_p(log + 28), ==, 45);
    g_assert_cmpuint(ldl_le_p(log + 56), ==, 4);
    for (i = 0; i < ARRAY_SIZE(expected_banks); i++) {
        g_assert_cmphex(lduw_le_p(log + 60 + 4 * i), ==, expected_banks[i]);
        g_assert_cmpuint(lduw_le_p(log + 62 + 4 * i), ==,
                         digest_size(expected_banks[i]));
    }
    g_assert_cmpuint(log[76], ==, 0);
    offset = 77;
    for (i = 0; i < virt_drtm_measurement_manifest_event_count(manifest); i++) {
        manifest_event = virt_drtm_measurement_manifest_event(manifest, i);
        offset = parse_event(log, size, offset, &parsed);
        g_assert_cmpuint(parsed.pcr, ==, manifest_event->pcr);
        g_assert_cmphex(parsed.type, ==, manifest_event->type);
        g_assert_cmpuint(parsed.digest_count, ==,
                         manifest_event->digest_count);
        for (j = 0; j < parsed.digest_count; j++) {
            g_assert_cmphex(parsed.algorithms[j], ==,
                            manifest_event->digests[j].algorithm);
            g_assert_cmpmem(parsed.digests[j], parsed.digest_sizes[j],
                            manifest_event->digests[j].value,
                            manifest_event->digests[j].size);
        }
    }
    g_assert_cmpuint(offset, ==, size);

    fixture_init(&reordered, 0xb);
    memcpy(reordered.banks, expected_banks, sizeof(expected_banks));
    reordered.input.active_bank_count = ARRAY_SIZE(expected_banks);
    second_log = build(&reordered, &second_size);
    g_assert_cmpmem(log, size, second_log, second_size);
    g_free(second_log);
    g_free(log);
    virt_drtm_measurement_manifest_free(manifest);
}

static void test_default_order_and_bytes(void)
{
    static const uint8_t separator[] = "ARM_DRTM";
    static const uint8_t zero_dce_event_digest[32] = {
        0x14, 0x06, 0xe0, 0x58, 0x81, 0xe2, 0x99, 0x36,
        0x77, 0x66, 0xd3, 0x13, 0xe2, 0x6c, 0x05, 0x56,
        0x4e, 0xc9, 0x1b, 0xf7, 0x21, 0xd3, 0x17, 0x26,
        0xbd, 0x6e, 0x46, 0xe6, 0x06, 0x89, 0x53, 0x9a,
    };
    uint8_t zero = 0, one = 1, entry[8], dce_digest[64], *result = dce_digest;
    Fixture f;
    uint8_t *log;
    size_t size, offset = 65, dce_digest_size = 32;

    fixture_init(&f, 0xb);
    log = build(&f, &size);
    check_spec(log, 0xb);
    g_assert_cmpint(qcrypto_hash_bytes(QCRYPTO_HASH_ALGO_SHA256, &zero, 1,
                                       &result, &dce_digest_size,
                                       &error_abort), ==, 0);
    {
        ParsedEvent event;
        offset = parse_event(log, size, offset, &event);
    g_assert_cmpuint(event.pcr, ==, 17);
    g_assert_cmphex(event.type, ==, VIRT_DRTM_EV_DCE);
    expect_hash(0xb, dce_digest, 32, event.digest);
    g_assert_cmpmem(event.digest, 32, zero_dce_event_digest, 32);
        g_assert_cmpuint(event.data_size, ==, 34);
        g_assert_cmpuint(lduw_le_p(event.data), ==, 0xb);
        g_assert_cmpmem(event.data + 2, 32, dce_digest, 32);
    }
    offset = check_event(log, size, offset, 17, VIRT_DRTM_EV_PCR_SCHEMA,
                         &one, 1, &one, 1);
    offset = check_event(log, size, offset, 17, VIRT_DRTM_EV_SEPARATOR,
                         separator, 8, separator, 8);
    offset = check_event(log, size, offset, 18, VIRT_DRTM_EV_PCR_SCHEMA,
                         &one, 1, &one, 1);
    offset = check_event(log, size, offset, 18, VIRT_DRTM_EV_DCE_PUBKEY,
                         &zero, 1, NULL, 0);
    offset = check_event(log, size, offset, 18, VIRT_DRTM_EV_DEBUG_CONFIG,
                         &one, 1, &one, 1);
    offset = check_event(log, size, offset, 18,
                         VIRT_DRTM_EV_NONSECURE_CONFIG, &zero, 1, &zero, 1);
    offset = check_event(log, size, offset, 18, VIRT_DRTM_EV_DLME,
                         f.dlme, sizeof(f.dlme), NULL, 0);
    stq_le_p(entry, f.input.dlme_entry_point_offset);
    offset = check_event(log, size, offset, 18,
                         VIRT_DRTM_EV_DLME_ENTRY_POINT,
                         entry, 8, entry, 8);
    offset = check_event(log, size, offset, 18, VIRT_DRTM_EV_SEPARATOR,
                         separator, 8, separator, 8);
    g_assert_cmpuint(offset, ==, size);
    g_free(log);
}

static void test_optional_and_distinct(void)
{
    static const uint8_t dce[] = { 1, 2, 3 };
    static const uint8_t key[] = { 4, 5 };
    static const uint8_t cert[] = { 6, 7, 8, 9 };
    static const uint8_t fw[] = { 10, 11 };
    static const uint8_t name[] = "EL3";
    VirtDRTMMeasuredComponent tzfw = { { fw, sizeof(fw) },
                                       { name, sizeof(name) - 1 } };
    static const uint8_t separator[] = "ARM_DRTM";
    uint8_t zero = 0, one = 1, entry[8], dce_digest[64];
    uint8_t *result = dce_digest;
    Fixture f;
    ParsedEvent event;
    uint8_t *log;
    size_t size, offset = 65, dce_digest_size = 48;

    fixture_init(&f, 0xc);
    f.input.dce_image = (VirtDRTMBlob) { dce, sizeof(dce) };
    f.input.dce_public_key = (VirtDRTMBlob) { key, sizeof(key) };
    f.input.dce_certificate_chain = (VirtDRTMBlob) { cert, sizeof(cert) };
    f.input.tzfw = &tzfw;
    f.input.tzfw_count = 1;
    f.input.secure_interrupts_disabled = true;
    log = build(&f, &size);
    check_spec(log, 0xc);
    g_assert_cmpint(qcrypto_hash_bytes(QCRYPTO_HASH_ALGO_SHA384,
                                       dce, sizeof(dce), &result,
                                       &dce_digest_size,
                                       &error_abort), ==, 0);
    offset = parse_event(log, size, offset, &event);
    g_assert_cmpuint(event.pcr, ==, 17);
    g_assert_cmphex(event.type, ==, VIRT_DRTM_EV_DCE);
    expect_hash(0xc, dce_digest, dce_digest_size, event.digest);
    g_assert_cmpuint(event.data_size, ==, dce_digest_size + 2);
    g_assert_cmpuint(lduw_le_p(event.data), ==, 0xc);
    g_assert_cmpmem(event.data + 2, dce_digest_size,
                    dce_digest, dce_digest_size);
    offset = check_event(log, size, offset, 17, VIRT_DRTM_EV_PCR_SCHEMA,
                         &one, 1, &one, 1);
    offset = check_event(log, size, offset, 17, VIRT_DRTM_EV_TZFW,
                         fw, sizeof(fw), name, sizeof(name) - 1);
    offset = check_event(log, size, offset, 17,
                         VIRT_DRTM_EV_SECURE_INT_DISABLE,
                         &one, 1, &one, 1);
    offset = check_event(log, size, offset, 17, VIRT_DRTM_EV_SEPARATOR,
                         separator, 8, separator, 8);
    offset = check_event(log, size, offset, 18, VIRT_DRTM_EV_PCR_SCHEMA,
                         &one, 1, &one, 1);
    offset = check_event(log, size, offset, 18, VIRT_DRTM_EV_DCE_PUBKEY,
                         key, sizeof(key), cert, sizeof(cert));
    offset = check_event(log, size, offset, 18, VIRT_DRTM_EV_DEBUG_CONFIG,
                         &one, 1, &one, 1);
    offset = check_event(log, size, offset, 18,
                         VIRT_DRTM_EV_NONSECURE_CONFIG, &zero, 1, &zero, 1);
    offset = check_event(log, size, offset, 18, VIRT_DRTM_EV_DLME,
                         f.dlme, sizeof(f.dlme), NULL, 0);
    stq_le_p(entry, f.input.dlme_entry_point_offset);
    offset = check_event(log, size, offset, 18,
                         VIRT_DRTM_EV_DLME_ENTRY_POINT,
                         entry, sizeof(entry), entry, sizeof(entry));
    offset = check_event(log, size, offset, 18, VIRT_DRTM_EV_SEPARATOR,
                         separator, 8, separator, 8);
    g_assert_cmpuint(offset, ==, size);
    g_free(log);
}

static void test_bounds_determinism_and_changes(void)
{
    Fixture f;
    uint8_t *a, *b, *short_buffer;
    size_t size, size2 = 0;

    fixture_init(&f, 0xd);
    a = build(&f, &size);
    b = build(&f, &size2);
    g_assert_cmpuint(size, ==, size2);
    g_assert_cmpmem(a, size, b, size2);
    short_buffer = g_malloc(size);
    memset(short_buffer, 0xa5, size);
    g_assert_cmpint(virt_drtm_event_log_build(&f.input, short_buffer, size - 1,
                                              &size2), ==,
                    VIRT_DRTM_EVENT_LOG_TOO_SMALL);
    g_assert_cmpuint(size2, ==, size);
    g_assert_cmphex(short_buffer[0], ==, 0xa5);
    f.dlme[0] ^= 1;
    g_assert_cmpint(virt_drtm_event_log_build(&f.input, b, size, &size2), ==,
                    VIRT_DRTM_EVENT_LOG_OK);
    g_assert_cmpint(memcmp(a, b, size), !=, 0);
    g_free(short_buffer);
    g_free(b);
    g_free(a);
}

static void test_algorithms_and_validation(void)
{
    static const uint16_t algorithms[] = { 0xb, 0xc, 0xd };
    Fixture f;
    uint8_t *log;
    size_t size, i;

    for (i = 0; i < ARRAY_SIZE(algorithms); i++) {
        fixture_init(&f, algorithms[i]);
        log = build(&f, &size);
        check_spec(log, algorithms[i]);
        g_free(log);
    }
    fixture_init(&f, 4);
    g_assert_cmpint(virt_drtm_event_log_build(&f.input, NULL, 0, &size), ==,
                    VIRT_DRTM_EVENT_LOG_INVALID);
    fixture_init(&f, 0xb);
    f.input.dlme_image.data = NULL;
    g_assert_cmpint(virt_drtm_event_log_build(&f.input, NULL, 0, &size), ==,
                    VIRT_DRTM_EVENT_LOG_INVALID);
    fixture_init(&f, 0xb);
    f.input.dce_public_key = (VirtDRTMBlob) { f.dlme, 1 };
    g_assert_cmpint(virt_drtm_event_log_build(&f.input, NULL, 0, &size), ==,
                    VIRT_DRTM_EVENT_LOG_INVALID);
    fixture_init(&f, 0xb);
    f.input.pcr_schema_value = 0;
    g_assert_cmpint(virt_drtm_event_log_build(&f.input, NULL, 0, &size), ==,
                    VIRT_DRTM_EVENT_LOG_INVALID);
    f.input.pcr_schema_value = 2;
    g_assert_cmpint(virt_drtm_event_log_build(&f.input, NULL, 0, &size), ==,
                    VIRT_DRTM_EVENT_LOG_INVALID);

    fixture_init(&f, 0xb);
    f.banks[1] = 0xb;
    f.input.active_bank_count = 2;
    g_assert_cmpint(virt_drtm_event_log_build(&f.input, NULL, 0, &size), ==,
                    VIRT_DRTM_EVENT_LOG_INVALID);
    f.banks[1] = 0x12; /* TPM_ALG_SM3_256 is not represented. */
    g_assert_cmpint(virt_drtm_event_log_build(&f.input, NULL, 0, &size), ==,
                    VIRT_DRTM_EVENT_LOG_INVALID);
    f.input.active_bank_count = 0;
    g_assert_cmpint(virt_drtm_event_log_build(&f.input, NULL, 0, &size), ==,
                    VIRT_DRTM_EVENT_LOG_INVALID);
}

static void test_launch_data_integration(void)
{
    static const uint32_t ids[] = {
        0x43495041, 0x4746434d, 0x54445447, 0x54524f49, 0x324d5054,
    };
    VirtDRTMMemoryRegion map = {
        0x40000000, 0x00400000, VIRT_DRTM_MEMORY_NORMAL_CACHED, 3
    };
    VirtDRTMTCBHash hashes[ARRAY_SIZE(ids)];
    uint8_t tcb_digests[ARRAY_SIZE(ids)][32] = { { 0 } };
    Fixture f;
    VirtDRTMDataInput data_input;
    uint8_t *event_log, *data;
    size_t event_size, data_size, event_offset, i;

    fixture_init(&f, 0xb);
    event_log = build(&f, &event_size);
    for (i = 0; i < ARRAY_SIZE(ids); i++) {
        hashes[i] = (VirtDRTMTCBHash) {
            .id = ids[i],
            .digest = tcb_digests[i],
            .digest_size = sizeof(tcb_digests[i]),
        };
    }
    data_input = (VirtDRTMDataInput) {
        .dlme_address = 0x40000000,
        .dlme_size = 0x00400000,
        .image_address = 0x40000000,
        .image_size = 0x00200000,
        .complete_protection = true,
        .address_map = &map,
        .address_map_count = 1,
        .event_log = { event_log, event_size },
        .firmware_hash_algorithm = VIRT_DRTM_TPM_ALG_SHA256,
        .tcb_hashes = hashes,
        .tcb_hash_count = ARRAY_SIZE(hashes),
    };
    g_assert_cmpint(virt_drtm_data_build(&data_input, 0x40200000, NULL, 0,
                                         &data_size), ==, VIRT_DRTM_DATA_OK);
    data = g_malloc(data_size);
    g_assert_cmpint(virt_drtm_data_build(&data_input, 0x40200000, data,
                                         data_size, &data_size), ==,
                    VIRT_DRTM_DATA_OK);
    event_offset = VIRT_DRTM_DATA_HEADER_SIZE + ldq_le_p(data + 16) +
                   ldq_le_p(data + 24);
    g_assert_cmpuint(ldq_le_p(data + 32), ==, event_size);
    g_assert_cmpmem(data + event_offset, event_size, event_log, event_size);
    g_free(data);
    g_free(event_log);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_assert_cmpint(qcrypto_init(&error_fatal), ==, 0);
    g_test_add_func("/virt-drtm-event-log/default",
                    test_default_order_and_bytes);
    g_test_add_func("/virt-drtm-event-log/optional",
                    test_optional_and_distinct);
    g_test_add_func("/virt-drtm-event-log/multibank-manifest-replay",
                    test_multibank_manifest_and_replay);
    g_test_add_func("/virt-drtm-event-log/sha1-active-sha256-selected",
                    test_sha1_active_sha256_selected);
    g_test_add_func("/virt-drtm-event-log/bounds-determinism",
                    test_bounds_determinism_and_changes);
    g_test_add_func("/virt-drtm-event-log/algorithms-validation",
                    test_algorithms_and_validation);
    g_test_add_func("/virt-drtm-event-log/launch-data-integration",
                    test_launch_data_integration);
    return g_test_run();
}
