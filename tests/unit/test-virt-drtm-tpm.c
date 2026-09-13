/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/arm/virt-drtm-tpm.h"
#include "qapi/error.h"
#include "qemu/bswap.h"
#include "qemu/cutils.h"

typedef struct TestCall {
    bool hash;
    uint8_t locality;
    TPMBackendDRTMHashOperation hash_op;
    size_t size;
    uint8_t bytes[128];
} TestCall;

typedef struct Fixture {
    VirtDRTMMeasurementManifest *manifest;
    TestCall calls[64];
    size_t call_count;
    size_t fail_call;
    uint16_t response_tag;
    uint32_t response_size_field;
    uint32_t response_code;
    size_t response_size;
    uint32_t parameter_size;
    uint8_t response_attributes;
} Fixture;

static bool test_hash(void *opaque, uint8_t locality,
                      TPMBackendDRTMHashOperation operation,
                      const uint8_t *data, size_t data_size, Error **errp)
{
    Fixture *f = opaque;
    TestCall *call = &f->calls[f->call_count];

    call->hash = true;
    call->locality = locality;
    call->hash_op = operation;
    call->size = data_size;
    memcpy(call->bytes, data, data_size);
    if (f->call_count++ == f->fail_call) {
        error_setg(errp, "injected hash failure");
        return false;
    }
    return true;
}

static bool test_command(void *opaque, uint8_t locality,
                         const uint8_t *request, size_t request_size,
                         uint8_t *response, size_t *response_size,
                         Error **errp)
{
    Fixture *f = opaque;
    TestCall *call = &f->calls[f->call_count];

    call->locality = locality;
    call->size = request_size;
    memcpy(call->bytes, request, request_size);
    if (f->call_count++ == f->fail_call) {
        error_setg(errp, "injected command failure");
        return false;
    }
    g_assert_cmpuint(*response_size, >=, f->response_size);
    memset(response, 0, *response_size);
    stw_be_p(response, f->response_tag);
    stl_be_p(response + 2, f->response_size_field);
    stl_be_p(response + 6, f->response_code);
    stl_be_p(response + 10, f->parameter_size);
    response[16] = f->response_attributes;
    *response_size = f->response_size;
    return true;
}

static const VirtDRTMTPMOps test_ops = {
    .hash = test_hash,
    .command = test_command,
};

static void fixture_setup(Fixture *f, gconstpointer opaque)
{
    static const uint16_t banks[] = {
        VIRT_DRTM_TPM_ALG_SHA1, VIRT_DRTM_TPM_ALG_SHA256,
    };
    static const uint8_t dlme[] = { 0x11, 0x22, 0x33 };
    VirtDRTMEventLogInput input = {
        .active_banks = banks,
        .active_bank_count = G_N_ELEMENTS(banks),
        .pcr_schema_value = 1,
        .dlme_image = { dlme, sizeof(dlme) },
    };

    f->fail_call = SIZE_MAX;
    f->response_tag = 0x8002;
    f->response_size_field = 19;
    f->response_size = 19;
    f->response_attributes = 0x01;
    g_assert_cmpint(virt_drtm_measurement_manifest_build(&input, &f->manifest),
                    ==, VIRT_DRTM_EVENT_LOG_OK);
}

static void fixture_teardown(Fixture *f, gconstpointer opaque)
{
    virt_drtm_measurement_manifest_free(f->manifest);
}

static void test_execute(Fixture *f, gconstpointer opaque)
{
    VirtDRTMTPMResult result = virt_drtm_tpm_execute(
        f->manifest, &test_ops, f, &error_abort);
    const TestCall *call;
    size_t i;

    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_OK);
    g_assert_true(result.irreversible);
    g_assert_cmpuint(result.failed_operation, ==, SIZE_MAX);
    g_assert_cmpuint(f->call_count, ==,
        virt_drtm_measurement_manifest_operation_count(f->manifest));

    for (i = 0; i < 3; i++) {
        g_assert_true(f->calls[i].hash);
        g_assert_cmpuint(f->calls[i].locality, ==, 4);
        g_assert_cmpint(f->calls[i].hash_op, ==, i);
    }
    g_assert_cmpuint(f->calls[0].size, ==, 0);
    g_assert_cmpuint(f->calls[1].size, ==, 32);
    g_assert_cmpuint(f->calls[2].size, ==, 0);

    /* First cap: PCR17/SHA1/zero digest with password authorization. */
    call = &f->calls[3];
    g_assert_false(call->hash);
    g_assert_cmpuint(call->locality, ==, 3);
    g_assert_cmpuint(call->size, ==, 53);
    g_assert_cmphex(lduw_be_p(call->bytes), ==, 0x8002);
    g_assert_cmpuint(ldl_be_p(call->bytes + 2), ==, call->size);
    g_assert_cmphex(ldl_be_p(call->bytes + 6), ==, 0x182);
    g_assert_cmpuint(ldl_be_p(call->bytes + 10), ==, 17);
    g_assert_cmpuint(ldl_be_p(call->bytes + 14), ==, 9);
    g_assert_cmphex(ldl_be_p(call->bytes + 18), ==, 0x40000009);
    g_assert_cmpuint(lduw_be_p(call->bytes + 22), ==, 0);
    g_assert_cmpuint(call->bytes[24], ==, 0);
    g_assert_cmpuint(lduw_be_p(call->bytes + 25), ==, 0);
    g_assert_cmpuint(ldl_be_p(call->bytes + 27), ==, 1);
    g_assert_cmphex(lduw_be_p(call->bytes + 31), ==,
                    VIRT_DRTM_TPM_ALG_SHA1);
    g_assert_true(buffer_is_zero(call->bytes + 33, 20));

    /* The second cap is PCR18; all remaining commands use selected SHA256. */
    g_assert_cmpuint(ldl_be_p(f->calls[4].bytes + 10), ==, 18);
    for (i = 5; i < f->call_count; i++) {
        g_assert_cmpuint(f->calls[i].locality, ==, 3);
        g_assert_cmphex(lduw_be_p(f->calls[i].bytes + 31), ==,
                        VIRT_DRTM_TPM_ALG_SHA256);
        g_assert_cmpuint(f->calls[i].size, ==, 65);
    }
}

static void test_staged(Fixture *f, gconstpointer opaque)
{
    VirtDRTMTPMExecution execution;
    VirtDRTMTPMResult result;
    const VirtDRTMMeasurementOperation *first_dce_operation;
    bool dcrtm_has_pcr18_extend = false;
    size_t dce_operation =
        virt_drtm_measurement_manifest_dce_operation(f->manifest);
    size_t operation_count =
        virt_drtm_measurement_manifest_operation_count(f->manifest);

    g_assert_true(virt_drtm_tpm_execution_init(&execution, f->manifest,
                                                &error_abort));
    g_assert_cmpuint(f->call_count, ==, 0);
    result = virt_drtm_tpm_execute_hash(&execution, &test_ops, f,
                                        &error_abort);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_OK);
    g_assert_true(result.irreversible);
    g_assert_cmpuint(f->call_count, ==, 3);
    g_assert_cmpuint(execution.next_operation, ==, 3);
    for (size_t i = 0; i < f->call_count; i++) {
        g_assert_true(f->calls[i].hash);
        g_assert_cmpuint(f->calls[i].locality, ==, 4);
    }

    result = virt_drtm_tpm_execute_dcrtm_extends(&execution, &test_ops, f,
                                                 &error_abort);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_OK);
    g_assert_cmpuint(execution.next_operation, ==, dce_operation);
    g_assert_cmpuint(f->call_count, ==, dce_operation);
    for (size_t i = 3; i < dce_operation; i++) {
        const VirtDRTMMeasurementOperation *operation =
            virt_drtm_measurement_manifest_operation(f->manifest, i);

        dcrtm_has_pcr18_extend |=
            operation->type == VIRT_DRTM_MEASUREMENT_PCR_EXTEND &&
            operation->pcr == 18;
    }
    g_assert_true(dcrtm_has_pcr18_extend);
    first_dce_operation = virt_drtm_measurement_manifest_operation(
        f->manifest, dce_operation);
    g_assert_cmpint(first_dce_operation->type, ==,
                    VIRT_DRTM_MEASUREMENT_PCR_EXTEND);
    g_assert_cmpuint(first_dce_operation->pcr, ==, 17);
    result = virt_drtm_tpm_execute_dce_extends(&execution, &test_ops, f,
                                               &error_abort);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_OK);
    g_assert_true(result.irreversible);
    g_assert_cmpuint(f->call_count, ==, operation_count);
    g_assert_cmpuint(ldl_be_p(f->calls[dce_operation].bytes + 10), ==, 17);
    g_assert_cmpmem(f->calls[dce_operation].bytes + 33,
                    first_dce_operation->digest.size,
                    first_dce_operation->digest.value,
                    first_dce_operation->digest.size);
    for (size_t i = 3; i < f->call_count; i++) {
        g_assert_false(f->calls[i].hash);
        g_assert_cmpuint(f->calls[i].locality, ==, 3);
    }
}

static void test_staged_failure_poison(Fixture *f, gconstpointer opaque)
{
    VirtDRTMTPMExecution execution;
    VirtDRTMTPMResult result;
    Error *err = NULL;
    size_t failed_call_count;

    g_assert_true(virt_drtm_tpm_execution_init(&execution, f->manifest,
                                                &error_abort));
    f->fail_call = 0;
    result = virt_drtm_tpm_execute_hash(&execution, &test_ops, f, &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_HASH_ERROR);
    g_assert_true(result.irreversible);
    g_assert_true(execution.failed);
    error_free(err);
    err = NULL;
    failed_call_count = f->call_count;
    result = virt_drtm_tpm_execute_hash(&execution, &test_ops, f, &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_INVALID);
    g_assert_cmpuint(f->call_count, ==, failed_call_count);
    g_assert_nonnull(err);
    error_free(err);

    memset(f->calls, 0, sizeof(f->calls));
    f->call_count = 0;
    f->fail_call = 3;
    g_assert_true(virt_drtm_tpm_execution_init(&execution, f->manifest,
                                                &error_abort));
    result = virt_drtm_tpm_execute_hash(&execution, &test_ops, f,
                                        &error_abort);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_OK);
    err = NULL;
    result = virt_drtm_tpm_execute_dcrtm_extends(&execution, &test_ops, f,
                                                 &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_TRANSPORT_ERROR);
    g_assert_true(execution.failed);
    error_free(err);
    err = NULL;
    failed_call_count = f->call_count;
    result = virt_drtm_tpm_execute_dcrtm_extends(&execution, &test_ops, f,
                                                 &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_INVALID);
    g_assert_cmpuint(f->call_count, ==, failed_call_count);
    g_assert_nonnull(err);
    error_free(err);

    memset(f->calls, 0, sizeof(f->calls));
    f->call_count = 0;
    f->fail_call = virt_drtm_measurement_manifest_dce_operation(f->manifest);
    g_assert_true(virt_drtm_tpm_execution_init(&execution, f->manifest,
                                                &error_abort));
    result = virt_drtm_tpm_execute_hash(&execution, &test_ops, f,
                                        &error_abort);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_OK);
    result = virt_drtm_tpm_execute_dcrtm_extends(&execution, &test_ops, f,
                                                 &error_abort);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_OK);
    err = NULL;
    result = virt_drtm_tpm_execute_dce_extends(&execution, &test_ops, f,
                                               &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_TRANSPORT_ERROR);
    g_assert_cmpuint(result.failed_operation, ==, f->fail_call);
    g_assert_true(execution.failed);
    error_free(err);
}

static void test_combined_atomic_validation(Fixture *f, gconstpointer opaque)
{
    const VirtDRTMTPMOps incomplete_ops = { .hash = test_hash };
    VirtDRTMTPMResult result;
    Error *err = NULL;

    result = virt_drtm_tpm_execute(f->manifest, &incomplete_ops, f, &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_INVALID);
    g_assert_false(result.irreversible);
    g_assert_cmpuint(result.failed_operation, ==, SIZE_MAX);
    g_assert_cmpuint(f->call_count, ==, 0);
    g_assert_nonnull(err);
    error_free(err);
}

static void test_failures(Fixture *f, gconstpointer opaque)
{
    VirtDRTMTPMResult result;
    Error *err = NULL;

    f->fail_call = 0;
    result = virt_drtm_tpm_execute(f->manifest, &test_ops, f, &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_HASH_ERROR);
    g_assert_true(result.irreversible);
    g_assert_cmpuint(result.failed_operation, ==, 0);
    g_assert_nonnull(err);
    error_free(err);

    memset(f->calls, 0, sizeof(f->calls));
    f->call_count = 0;
    f->fail_call = 3;
    err = NULL;
    result = virt_drtm_tpm_execute(f->manifest, &test_ops, f, &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_TRANSPORT_ERROR);
    g_assert_true(result.irreversible);
    g_assert_cmpuint(result.failed_operation, ==, 3);
    g_assert_nonnull(err);
    error_free(err);
}

static void test_responses(Fixture *f, gconstpointer opaque)
{
    VirtDRTMTPMResult result;
    Error *err = NULL;

    f->response_code = 0x101;
    result = virt_drtm_tpm_execute(f->manifest, &test_ops, f, &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_RESPONSE_ERROR);
    g_assert_cmphex(result.response_code, ==, 0x101);
    g_assert_true(result.irreversible);
    g_assert_nonnull(err);
    error_free(err);

    memset(f->calls, 0, sizeof(f->calls));
    f->call_count = 0;
    f->response_code = 0;
    f->response_tag = 0x8001;
    err = NULL;
    result = virt_drtm_tpm_execute(f->manifest, &test_ops, f, &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_RESPONSE_ERROR);
    error_free(err);
}

static void test_response_attributes(Fixture *f, gconstpointer opaque)
{
    static const uint8_t invalid_attributes[] = { 0x00, 0x02, 0x80 };

    for (size_t i = 0; i < G_N_ELEMENTS(invalid_attributes); i++) {
        VirtDRTMTPMResult result;
        Error *err = NULL;

        memset(f->calls, 0, sizeof(f->calls));
        f->call_count = 0;
        f->response_attributes = invalid_attributes[i];
        result = virt_drtm_tpm_execute(f->manifest, &test_ops, f, &err);
        g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_RESPONSE_ERROR);
        g_assert_true(result.irreversible);
        g_assert_nonnull(err);
        error_free(err);
    }
}

static void test_invalid(void)
{
    VirtDRTMTPMResult result;
    Error *err = NULL;

    result = virt_drtm_tpm_execute(NULL, &test_ops, NULL, &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_INVALID);
    g_assert_false(result.irreversible);
    g_assert_nonnull(err);
    error_free(err);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add("/virt-drtm-tpm/execute", Fixture, NULL,
               fixture_setup, test_execute, fixture_teardown);
    g_test_add("/virt-drtm-tpm/failures", Fixture, NULL,
               fixture_setup, test_failures, fixture_teardown);
    g_test_add("/virt-drtm-tpm/responses", Fixture, NULL,
               fixture_setup, test_responses, fixture_teardown);
    g_test_add("/virt-drtm-tpm/response-attributes", Fixture, NULL,
               fixture_setup, test_response_attributes, fixture_teardown);
    g_test_add("/virt-drtm-tpm/staged", Fixture, NULL,
               fixture_setup, test_staged, fixture_teardown);
    g_test_add("/virt-drtm-tpm/staged-failure-poison", Fixture, NULL,
               fixture_setup, test_staged_failure_poison, fixture_teardown);
    g_test_add("/virt-drtm-tpm/combined-atomic-validation", Fixture, NULL,
               fixture_setup, test_combined_atomic_validation,
               fixture_teardown);
    g_test_add_func("/virt-drtm-tpm/invalid", test_invalid);
    return g_test_run();
}
