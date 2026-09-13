/*
 * TPM platform command transport tests
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"
#include "system/tpm.h"
#include "system/tpm_util.h"

#define TYPE_TEST_TPM "test-tpm-platform"
OBJECT_DECLARE_SIMPLE_TYPE(TestTPM, TEST_TPM)

struct TestTPM {
    Object parent;
    TPMVersion version;
    bool fail_transport;
    uint16_t response_tag;
    uint32_t response_size;
    size_t actual_size;
    uint32_t response_code;
    unsigned int calls;
    uint8_t locality;
    bool drtm_enabled;
    bool no_active;
    bool localities_open;
    TPMDRTMLocalityCloseResult close_result;
    bool locality2_active;
};

static enum TPMVersion test_tpm_get_version(TPMIf *ti)
{
    return TEST_TPM(ti)->version;
}

static bool test_tpm_deliver(TPMIf *ti, uint8_t locality,
                             const uint8_t *request, size_t request_size,
                             uint8_t *response, size_t *response_size,
                             Error **errp)
{
    TestTPM *s = TEST_TPM(ti);

    s->calls++;
    s->locality = locality;
    if (s->fail_transport) {
        return false;
    }

    g_assert_cmpuint(*response_size, >=, 10);
    tpm_cmd_set_tag(response, s->response_tag);
    stl_be_p(response + 2, s->response_size);
    stl_be_p(response + 6, s->response_code);
    *response_size = s->actual_size;
    return true;
}

static bool test_tpm_enable_drtm(TPMIf *ti, Error **errp)
{
    TEST_TPM(ti)->drtm_enabled = true;
    return true;
}

static bool test_tpm_no_active(TPMIf *ti, bool *no_active, Error **errp)
{
    *no_active = TEST_TPM(ti)->no_active;
    return true;
}

static bool test_tpm_open_localities(TPMIf *ti, Error **errp)
{
    TEST_TPM(ti)->localities_open = true;
    return true;
}

static bool test_tpm_close_locality(TPMIf *ti, uint8_t locality,
                                    TPMDRTMLocalityCloseResult *result,
                                    Error **errp)
{
    TestTPM *s = TEST_TPM(ti);

    s->locality = locality;
    *result = s->close_result;
    return true;
}

static bool test_tpm_activate_locality2(TPMIf *ti, Error **errp)
{
    TEST_TPM(ti)->locality2_active = true;
    return true;
}

static void test_tpm_iface_init(ObjectClass *klass, const void *data)
{
    TPMIfClass *tc = TPM_IF_CLASS(klass);

    tc->get_version = test_tpm_get_version;
    tc->deliver_platform_request = test_tpm_deliver;
    tc->enable_drtm = test_tpm_enable_drtm;
    tc->drtm_no_active_locality = test_tpm_no_active;
    tc->drtm_open_localities = test_tpm_open_localities;
    tc->drtm_close_locality = test_tpm_close_locality;
    tc->drtm_activate_locality2 = test_tpm_activate_locality2;
}

static const TypeInfo test_tpm_info = {
    .name = TYPE_TEST_TPM,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(TestTPM),
    .class_init = test_tpm_iface_init,
    .interfaces = (const InterfaceInfo[]) {
        { TYPE_TPM_IF },
        { }
    },
};

static const TypeInfo test_tpm_if_info = {
    .name = TYPE_TPM_IF,
    .parent = TYPE_INTERFACE,
    .class_size = sizeof(TPMIfClass),
};

static TestTPM *test_tpm_new(void)
{
    TestTPM *s = TEST_TPM(object_new(TYPE_TEST_TPM));

    s->version = TPM_VERSION_2_0;
    s->response_tag = 0x8001;
    s->response_size = 10;
    s->actual_size = 10;
    return s;
}

static void make_request(uint8_t request[10])
{
    tpm_cmd_set_tag(request, 0x8001);
    stl_be_p(request + 2, 10);
    stl_be_p(request + 6, 0x17a);
}

static void test_valid(void)
{
    g_autoptr(TestTPM) s = test_tpm_new();
    uint8_t request[10];
    uint8_t response[32] = { 0 };
    size_t response_size = sizeof(response);
    uint32_t response_code = UINT32_MAX;

    make_request(request);
    g_assert_true(tpm_deliver_platform_request(TPM_IF(s), 2,
                                               request, sizeof(request),
                                               response, &response_size,
                                               &response_code, &error_abort));
    g_assert_cmpuint(s->calls, ==, 1);
    g_assert_cmpuint(s->locality, ==, 2);
    g_assert_cmpuint(response_size, ==, 10);
    g_assert_cmphex(response_code, ==, 0);
}

static void test_tpm_error_is_a_response(void)
{
    g_autoptr(TestTPM) s = test_tpm_new();
    uint8_t request[10];
    uint8_t response[10] = { 0 };
    size_t response_size = sizeof(response);
    uint32_t response_code;

    make_request(request);
    s->response_code = 0x101;
    g_assert_true(tpm_deliver_platform_request(TPM_IF(s), 4,
                                               request, sizeof(request),
                                               response, &response_size,
                                               &response_code, &error_abort));
    g_assert_cmphex(response_code, ==, 0x101);
}

static void assert_rejected(TestTPM *s, uint8_t locality,
                            uint8_t *request, size_t request_size,
                            size_t response_capacity)
{
    uint8_t response[32] = { 0 };
    size_t response_size = response_capacity;
    Error *err = NULL;

    g_assert_false(tpm_deliver_platform_request(TPM_IF(s), locality,
                                                request, request_size,
                                                response, &response_size,
                                                NULL, &err));
    g_assert_nonnull(err);
    g_assert_cmpuint(response_size, ==, 0);
    error_free(err);
}

static void test_bad_requests(void)
{
    g_autoptr(TestTPM) s = test_tpm_new();
    uint8_t request[10];

    make_request(request);
    assert_rejected(s, 5, request, sizeof(request), 32);
    assert_rejected(s, 0, request, sizeof(request) - 1, 32);
    assert_rejected(s, 0, request, sizeof(request), 9);

    tpm_cmd_set_tag(request, 0x00c1);
    assert_rejected(s, 0, request, sizeof(request), 32);
    make_request(request);
    stl_be_p(request + 2, 11);
    assert_rejected(s, 0, request, sizeof(request), 32);
    g_assert_cmpuint(s->calls, ==, 0);
}

static void test_bad_responses(void)
{
    g_autoptr(TestTPM) s = test_tpm_new();
    uint8_t request[10];

    make_request(request);
    s->response_tag = 0x00c4;
    assert_rejected(s, 0, request, sizeof(request), 32);

    s->response_tag = 0x8001;
    s->actual_size = 9;
    assert_rejected(s, 0, request, sizeof(request), 32);

    s->actual_size = 33;
    assert_rejected(s, 0, request, sizeof(request), 32);

    s->actual_size = 10;
    s->response_size = 11;
    assert_rejected(s, 0, request, sizeof(request), 32);
}

static void test_frontend_failures(void)
{
    g_autoptr(TestTPM) s = test_tpm_new();
    uint8_t request[10];
    Error *err = NULL;

    make_request(request);
    s->version = TPM_VERSION_1_2;
    assert_rejected(s, 0, request, sizeof(request), 32);
    g_assert_cmpuint(s->calls, ==, 0);
    g_assert_false(tpm_enable_drtm(TPM_IF(s), &err));
    g_assert_nonnull(err);
    error_free(err);
    err = NULL;

    s->version = TPM_VERSION_2_0;
    s->fail_transport = true;
    assert_rejected(s, 0, request, sizeof(request), 32);
    g_assert_cmpuint(s->calls, ==, 1);
}

static void test_drtm_unsupported_frontend(void)
{
    g_autoptr(TestTPM) s = test_tpm_new();
    TPMIfClass *tc = TPM_IF_GET_CLASS(TPM_IF(s));
    bool (*enable_drtm)(TPMIf *, Error **) = tc->enable_drtm;
    Error *err = NULL;

    tc->enable_drtm = NULL;
    g_assert_false(tpm_enable_drtm(TPM_IF(s), &err));
    g_assert_nonnull(err);
    error_free(err);
    tc->enable_drtm = enable_drtm;
}

static void test_drtm_locality_frontend(void)
{
    g_autoptr(TestTPM) s = test_tpm_new();
    TPMDRTMLocalityCloseResult result;
    bool no_active;
    Error *err = NULL;

    s->no_active = true;
    s->close_result = TPM_DRTM_LOCALITY_NOT_RELINQUISHED;
    g_assert_true(tpm_enable_drtm(TPM_IF(s), &error_abort));
    g_assert_true(s->drtm_enabled);
    g_assert_true(tpm_drtm_no_active_locality(TPM_IF(s), &no_active,
                                              &error_abort));
    g_assert_true(no_active);
    g_assert_true(tpm_drtm_open_localities(TPM_IF(s), &error_abort));
    g_assert_true(s->localities_open);
    g_assert_true(tpm_drtm_close_locality(TPM_IF(s), 3, &result,
                                          &error_abort));
    g_assert_cmpuint(s->locality, ==, 3);
    g_assert_cmpint(result, ==, TPM_DRTM_LOCALITY_NOT_RELINQUISHED);
    g_assert_true(tpm_drtm_activate_locality2(TPM_IF(s), &error_abort));
    g_assert_true(s->locality2_active);

    g_assert_false(tpm_drtm_close_locality(TPM_IF(s), 1, &result, &err));
    g_assert_nonnull(err);
    error_free(err);
}

int main(int argc, char **argv)
{
    int ret;

    type_register_static(&test_tpm_if_info);
    type_register_static(&test_tpm_info);
    rust_bql_mock_lock();
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/tpm-platform/valid", test_valid);
    g_test_add_func("/tpm-platform/tpm-error", test_tpm_error_is_a_response);
    g_test_add_func("/tpm-platform/bad-requests", test_bad_requests);
    g_test_add_func("/tpm-platform/bad-responses", test_bad_responses);
    g_test_add_func("/tpm-platform/frontend-failures", test_frontend_failures);
    g_test_add_func("/tpm-platform/drtm-localities",
                    test_drtm_locality_frontend);
    g_test_add_func("/tpm-platform/drtm-unsupported",
                    test_drtm_unsupported_frontend);
    /* Unit tests run without vl.c's main-loop BQL setup. */
    ret = g_test_run();
    return ret;
}
