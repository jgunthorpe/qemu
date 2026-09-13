/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "hw/core/irq.h"
#include "hw/acpi/tpm.h"
#include "hw/tpm/tpm_tis.h"
#include "system/tpm_util.h"

static TPMState *test_state;
static TPMBackendCmd *test_pending;
static int test_completion_ret;
static unsigned int test_deliveries;
static bool test_timeout;
static unsigned int test_cancels;
static uint32_t test_platform_response_size;
static int test_irq_level;

static void test_irq_handler(void *opaque, int n, int level)
{
    test_irq_level = level;
}

void tpm_backend_deliver_request(TPMBackend *be, TPMBackendCmd *cmd)
{
    g_assert_null(test_pending);
    test_pending = cmd;
    test_deliveries++;
}

bool tpm_backend_finish_sync_timeout(TPMBackend *be, unsigned int timeout_ms)
{
    TPMBackendCmd *cmd = test_pending;

    if (!cmd) {
        return true;
    }
    if (test_timeout) {
        tpm_backend_cancel_cmd(be);
        return false;
    }
    test_pending = NULL;
    if (test_completion_ret == 0) {
        tpm_cmd_set_tag(cmd->out, 0x8001);
        stl_be_p(cmd->out + 2,
                 cmd == &test_state->platform_cmd ?
                 test_platform_response_size : 10);
        stl_be_p(cmd->out + 6,
                 cmd == &test_state->platform_cmd ? 0x123 : 0);
    }
    tpm_tis_request_completed(test_state, test_completion_ret);
    return true;
}

void tpm_backend_finish_sync(TPMBackend *be)
{
    tpm_backend_finish_sync_timeout(be, UINT_MAX);
}

bool tpm_backend_had_startup_error(TPMBackend *be)
{
    return false;
}

void tpm_backend_cancel_cmd(TPMBackend *be)
{
    test_cancels++;
}

bool tpm_backend_get_tpm_established_flag(TPMBackend *be)
{
    return false;
}

int tpm_backend_reset_tpm_established_flag(TPMBackend *be, uint8_t locality)
{
    return 0;
}

TPMVersion tpm_backend_get_tpm_version(TPMBackend *be)
{
    return TPM_VERSION_2_0;
}

size_t tpm_backend_get_buffer_size(TPMBackend *be)
{
    return TPM_TIS_BUFFER_MAX;
}

void tpm_backend_reset(TPMBackend *be)
{
}

int tpm_backend_startup_tpm(TPMBackend *be, size_t buffer_size)
{
    return 0;
}

void tpm_ppi_reset(TPMPPI *tpmppi)
{
}

void tpm_util_show_buffer(const unsigned char *buffer, size_t buffer_size,
                          const char *string)
{
}

static void make_command(uint8_t command[10])
{
    tpm_cmd_set_tag(command, 0x8001);
    stl_be_p(command + 2, 10);
    stl_be_p(command + 6, 0x17a);
}

static void setup_state(TPMState *s, TPMBackend *be)
{
    unsigned int i;

    memset(s, 0, sizeof(*s));
    s->be_driver = be;
    s->be_buffer_size = TPM_TIS_BUFFER_MAX;
    s->active_locty = TPM_TIS_NO_LOCALITY;
    s->next_locty = TPM_TIS_NO_LOCALITY;
    s->aborting_locty = TPM_TIS_NO_LOCALITY;
    for (i = 0; i < TPM_TIS_NUM_LOCALITIES; i++) {
        s->loc[i].access = TPM_TIS_ACCESS_TPM_REG_VALID_STS;
    }
    test_state = s;
    test_pending = NULL;
    test_completion_ret = 0;
    test_deliveries = 0;
    test_timeout = false;
    test_cancels = 0;
    test_platform_response_size = 10;
}

static void test_drtm_enable_and_guest_access(void)
{
    TPMState s;
    TPMBackend be = { };
    bool no_active;

    setup_state(&s, &be);
    g_assert_true(tpm_tis_enable_drtm(&s, &error_abort));
    g_assert_true(tpm_tis_drtm_no_active_locality(&s, &no_active,
                                                  &error_abort));
    g_assert_true(no_active);

    /* Closed dynamic localities ignore ACCESS, but locality 0 is unchanged. */
    tpm_tis_write_data(&s, 2 << TPM_TIS_LOCALITY_SHIFT,
                       TPM_TIS_ACCESS_REQUEST_USE, 1);
    g_assert_cmpuint(s.active_locty, ==, TPM_TIS_NO_LOCALITY);
    g_assert_cmphex(tpm_tis_read_data(&s, 2 << TPM_TIS_LOCALITY_SHIFT, 1),
                    ==, TPM_TIS_ACCESS_TPM_REG_VALID_STS |
                        TPM_TIS_ACCESS_TPM_ESTABLISHMENT);

    tpm_tis_write_data(&s, TPM_TIS_REG_ACCESS,
                       TPM_TIS_ACCESS_REQUEST_USE, 1);
    g_assert_cmpuint(s.active_locty, ==, 0);
}

static void test_drtm_open_is_atomic(void)
{
    TPMState s;
    TPMBackend be = { };
    uint8_t closed;
    Error *err = NULL;

    setup_state(&s, &be);
    g_assert_true(tpm_tis_enable_drtm(&s, &error_abort));
    closed = s.drtm_closed_localities;
    s.active_locty = 0;
    g_assert_false(tpm_tis_drtm_open_localities(&s, &err));
    g_assert_nonnull(err);
    g_assert_cmphex(s.drtm_closed_localities, ==, closed);
    error_free(err);

    s.active_locty = TPM_TIS_NO_LOCALITY;
    g_assert_true(tpm_tis_drtm_open_localities(&s, &error_abort));
    g_assert_cmphex(s.drtm_closed_localities, ==, 0);
}

static void test_drtm_close_and_activate(void)
{
    TPMState s;
    TPMBackend be = { };
    TPMDRTMLocalityCloseResult result;

    setup_state(&s, &be);
    g_assert_true(tpm_tis_enable_drtm(&s, &error_abort));
    g_assert_true(tpm_tis_drtm_open_localities(&s, &error_abort));

    /* Closing an idle locality must not scrub another active locality. */
    s.active_locty = 0;
    memset(s.buffer, 0x7e, sizeof(s.buffer));
    g_assert_true(tpm_tis_drtm_close_locality(&s, 3, &result,
                                              &error_abort));
    g_assert_cmphex(s.buffer[0], ==, 0x7e);
    s.active_locty = TPM_TIS_NO_LOCALITY;
    g_assert_true(tpm_tis_drtm_open_localities(&s, &error_abort));

    memset(s.buffer, 0xa5, sizeof(s.buffer));
    memset(s.platform_request, 0x5a, sizeof(s.platform_request));
    memset(s.platform_response, 0x3c, sizeof(s.platform_response));
    s.rw_offset = 17;
    g_assert_true(tpm_tis_drtm_close_locality(&s, 3, &result,
                                              &error_abort));
    g_assert_cmpint(result, ==, TPM_DRTM_LOCALITY_CLOSED);
    g_assert_cmpuint(s.rw_offset, ==, 0);
    g_assert_cmphex(s.buffer[0], ==, 0);
    g_assert_cmphex(s.platform_request[0], ==, 0);
    g_assert_cmphex(s.platform_response[0], ==, 0);
    g_assert_true(tpm_tis_drtm_close_locality(&s, 3, &result,
                                              &error_abort));
    g_assert_cmpint(result, ==, TPM_DRTM_LOCALITY_ALREADY_CLOSED);

    g_assert_true(tpm_tis_drtm_activate_locality2(&s, &error_abort));
    g_assert_cmpuint(s.active_locty, ==, 2);
    g_assert_true(tpm_tis_drtm_close_locality(&s, 2, &result,
                                              &error_abort));
    g_assert_cmpint(result, ==, TPM_DRTM_LOCALITY_NOT_RELINQUISHED);

    /* The guest relinquishes locality 2 through the ordinary TIS ACCESS bit. */
    tpm_tis_write_data(&s, (2 << TPM_TIS_LOCALITY_SHIFT) |
                           TPM_TIS_REG_ACCESS,
                       TPM_TIS_ACCESS_ACTIVE_LOCALITY, 1);
    g_assert_cmpuint(s.active_locty, ==, TPM_TIS_NO_LOCALITY);
    g_assert_true(tpm_tis_drtm_close_locality(&s, 2, &result,
                                              &error_abort));
    g_assert_cmpint(result, ==, TPM_DRTM_LOCALITY_CLOSED);
}

static void test_without_drtm_unchanged(void)
{
    TPMState s;
    TPMBackend be = { };

    setup_state(&s, &be);
    g_assert_false(s.drtm_enabled);
    tpm_tis_write_data(&s, 2 << TPM_TIS_LOCALITY_SHIFT,
                       TPM_TIS_ACCESS_REQUEST_USE, 1);
    g_assert_cmpuint(s.active_locty, ==, 2);
    g_assert_cmphex(tpm_tis_read_data(&s, 2 << TPM_TIS_LOCALITY_SHIFT, 1) &
                                         TPM_TIS_ACCESS_ACTIVE_LOCALITY,
                    ==, TPM_TIS_ACCESS_ACTIVE_LOCALITY);
}

static void test_drtm_reset_and_locality4(void)
{
    TPMState s;
    TPMBackend be = { };
    uint32_t access;
    IRQState irq = {
        .handler = test_irq_handler,
    };

    setup_state(&s, &be);
    s.irq = &irq;
    g_assert_true(tpm_tis_enable_drtm(&s, &error_abort));
    g_assert_true(tpm_tis_drtm_open_localities(&s, &error_abort));
    s.loc[3].inte = TPM_TIS_INT_ENABLED | TPM_TIS_INT_DATA_AVAILABLE;
    s.loc[3].ints = TPM_TIS_INT_DATA_AVAILABLE;
    qemu_irq_raise(s.irq);
    g_assert_cmpint(test_irq_level, ==, 1);
    tpm_tis_reset(&s, false);
    g_assert_cmpint(test_irq_level, ==, 0);
    g_assert_cmphex(s.drtm_closed_localities, ==,
                    (1U << 1) | (1U << 2) | (1U << 3));

    s.loc[0].access |= TPM_TIS_ACCESS_REQUEST_USE;
    access = tpm_tis_read_data(&s, 4 << TPM_TIS_LOCALITY_SHIFT, 1);
    g_assert_cmphex(access, ==, TPM_TIS_ACCESS_TPM_REG_VALID_STS |
                                    TPM_TIS_ACCESS_TPM_ESTABLISHMENT);
    tpm_tis_write_data(&s, 4 << TPM_TIS_LOCALITY_SHIFT,
                       TPM_TIS_ACCESS_REQUEST_USE, 1);
    g_assert_cmpuint(s.active_locty, ==, TPM_TIS_NO_LOCALITY);
    g_assert_cmphex(tpm_tis_read_data(&s, (4 << TPM_TIS_LOCALITY_SHIFT) |
                                         TPM_TIS_REG_STS, 4),
                    ==, UINT32_MAX);
    g_assert_cmphex(tpm_tis_read_data(&s, (4 << TPM_TIS_LOCALITY_SHIFT) |
                                         TPM_TIS_REG_DATA_FIFO, 1),
                    ==, UINT32_MAX);
}

static void test_drtm_inflight_and_late_completion(void)
{
    TPMState s;
    TPMBackend be = { };
    TPMDRTMLocalityCloseResult result;
    bool no_active;
    Error *err = NULL;

    setup_state(&s, &be);
    g_assert_true(tpm_tis_enable_drtm(&s, &error_abort));
    g_assert_true(tpm_tis_drtm_open_localities(&s, &error_abort));
    s.cmd.locty = 3;
    s.loc[3].state = TPM_TIS_STATE_EXECUTION;

    g_assert_true(tpm_tis_drtm_no_active_locality(&s, &no_active,
                                                  &error_abort));
    g_assert_false(no_active);
    g_assert_true(tpm_tis_drtm_close_locality(&s, 3, &result,
                                              &error_abort));
    g_assert_cmpint(result, ==, TPM_DRTM_LOCALITY_NOT_RELINQUISHED);
    g_assert_false(tpm_tis_drtm_activate_locality2(&s, &err));
    g_assert_nonnull(err);
    error_free(err);

    /* Reset closes the locality; a stale completion must be scrubbed. */
    tpm_tis_reset(&s, false);
    memset(s.buffer, 0xa5, sizeof(s.buffer));
    tpm_tis_request_completed(&s, 0);
    g_assert_cmphex(s.buffer[0], ==, 0);
    g_assert_cmpint(s.loc[3].state, ==, TPM_TIS_STATE_IDLE);
    g_assert_cmphex(s.loc[3].sts & TPM_TIS_STS_DATA_AVAILABLE, ==, 0);
}

static void test_drtm_close_reconciles_irq(void)
{
    TPMState s;
    TPMBackend be = { };
    TPMDRTMLocalityCloseResult result;
    IRQState irq = {
        .handler = test_irq_handler,
    };

    setup_state(&s, &be);
    s.irq = &irq;
    test_irq_level = 0;
    g_assert_true(tpm_tis_enable_drtm(&s, &error_abort));
    g_assert_true(tpm_tis_drtm_open_localities(&s, &error_abort));

    s.loc[3].inte = TPM_TIS_INT_ENABLED | TPM_TIS_INT_DATA_AVAILABLE;
    s.loc[3].ints = TPM_TIS_INT_DATA_AVAILABLE;
    qemu_irq_raise(s.irq);
    g_assert_cmpint(test_irq_level, ==, 1);
    g_assert_true(tpm_tis_drtm_close_locality(&s, 3, &result,
                                              &error_abort));
    g_assert_cmpint(test_irq_level, ==, 0);

    g_assert_true(tpm_tis_drtm_open_localities(&s, &error_abort));
    s.loc[0].inte = TPM_TIS_INT_ENABLED | TPM_TIS_INT_STS_VALID;
    s.loc[0].ints = TPM_TIS_INT_STS_VALID;
    s.loc[3].ints = TPM_TIS_INT_DATA_AVAILABLE;
    qemu_irq_raise(s.irq);
    g_assert_true(tpm_tis_drtm_close_locality(&s, 3, &result,
                                              &error_abort));
    g_assert_cmpint(test_irq_level, ==, 1);
}

static void test_drtm_closed_platform_command(void)
{
    TPMState s;
    TPMBackend be = { };
    uint8_t request[10];
    uint8_t response[10];
    size_t response_size = sizeof(response);
    Error *err = NULL;

    setup_state(&s, &be);
    make_command(request);
    g_assert_true(tpm_tis_enable_drtm(&s, &error_abort));
    g_assert_false(tpm_tis_deliver_platform_request(&s, 3,
                                                    request, sizeof(request),
                                                    response, &response_size,
                                                    &err));
    g_assert_nonnull(err);
    g_assert_cmpuint(test_deliveries, ==, 0);
    error_free(err);

    g_assert_true(tpm_tis_drtm_open_localities(&s, &error_abort));
    response_size = sizeof(response);
    g_assert_true(tpm_tis_deliver_platform_request(&s, 3,
                                                   request, sizeof(request),
                                                   response, &response_size,
                                                   &error_abort));
    g_assert_cmpuint(test_deliveries, ==, 1);
}

static void test_guest_then_platform(void)
{
    TPMState s;
    TPMBackend be = { };
    uint8_t request[10];
    uint8_t response[32] = { };
    size_t response_size = sizeof(response);

    setup_state(&s, &be);
    make_command(request);

    s.cmd.locty = 0;
    s.cmd.out = s.buffer;
    s.cmd.out_len = sizeof(s.buffer);
    test_pending = &s.cmd;

    g_assert_true(tpm_tis_deliver_platform_request(&s, 2,
                                                   request, sizeof(request),
                                                   response, &response_size,
                                                   &error_abort));
    g_assert_cmpuint(test_deliveries, ==, 1);
    g_assert_cmpuint(s.loc[0].state, ==, TPM_TIS_STATE_COMPLETION);
    g_assert_cmphex(tpm_cmd_get_errcode(s.buffer), ==, 0);
    g_assert_cmphex(tpm_cmd_get_errcode(response), ==, 0x123);
    g_assert_cmpuint(response_size, ==, 10);
    g_assert_false(s.platform_cmd_active);
}

static void test_failure_and_repeat(void)
{
    TPMState s;
    TPMBackend be = { };
    uint8_t request[10];
    uint8_t response[32] = { };
    size_t response_size = sizeof(response);
    Error *err = NULL;

    setup_state(&s, &be);
    make_command(request);
    test_completion_ret = -EIO;
    g_assert_false(tpm_tis_deliver_platform_request(&s, 4,
                                                    request, sizeof(request),
                                                    response, &response_size,
                                                    &err));
    error_free(err);

    test_completion_ret = 0;
    response_size = sizeof(response);
    g_assert_true(tpm_tis_deliver_platform_request(&s, 3,
                                                   request, sizeof(request),
                                                   response, &response_size,
                                                   &error_abort));
    g_assert_cmpuint(test_deliveries, ==, 2);
}

static void test_timeout_owns_buffers_and_queues_guest(void)
{
    TPMState s;
    TPMBackend be = { };
    uint8_t request[10];
    uint8_t response[32] = { };
    size_t response_size = sizeof(response);
    Error *err = NULL;
    TPMBackendCmd *platform_cmd;

    setup_state(&s, &be);
    make_command(request);
    test_timeout = true;
    g_assert_false(tpm_tis_deliver_platform_request(&s, 2,
                                                    request, sizeof(request),
                                                    response, &response_size,
                                                    &err));
    error_free(err);
    g_assert_true(s.platform_cmd_active);
    g_assert_cmpuint(test_cancels, ==, 1);
    g_assert_true(test_pending == &s.platform_cmd);
    g_assert_true(s.platform_cmd.in == s.platform_request);

    memset(request, 0xa5, sizeof(request));
    g_assert_cmpuint(s.platform_request[0], ==, 0x80);

    s.cmd.locty = 0;
    s.cmd.out = s.buffer;
    s.cmd.out_len = sizeof(s.buffer);
    s.guest_cmd_queued = true;
    platform_cmd = test_pending;
    test_pending = NULL;
    test_timeout = false;
    tpm_cmd_set_tag(platform_cmd->out, 0x8001);
    stl_be_p(platform_cmd->out + 2, 10);
    stl_be_p(platform_cmd->out + 6, 0);
    tpm_tis_request_completed(&s, 0);

    g_assert_false(s.platform_cmd_active);
    g_assert_true(test_pending == &s.cmd);
    g_assert_cmpuint(test_deliveries, ==, 2);
}

static void test_effective_response_capacity(void)
{
    TPMState s;
    TPMBackend be = { };
    uint8_t request[10];
    uint8_t response[16] = { };
    size_t response_size = sizeof(response);
    Error *err = NULL;

    setup_state(&s, &be);
    make_command(request);
    test_platform_response_size = sizeof(response) + 1;
    g_assert_false(tpm_tis_deliver_platform_request(&s, 2,
                                                    request, sizeof(request),
                                                    response, &response_size,
                                                    &err));
    g_assert_nonnull(err);
    g_assert_cmpuint(response_size, ==, 0);
    error_free(err);
}

static void test_queued_guest_cancel(void)
{
    TPMState s;
    TPMBackend be = { };

    setup_state(&s, &be);
    s.active_locty = 0;
    s.be_tpm_version = TPM_VERSION_2_0;
    s.loc[0].state = TPM_TIS_STATE_EXECUTION;
    s.guest_cmd_queued = true;
    s.platform_cmd_active = true;

    tpm_tis_write_data(&s, TPM_TIS_REG_STS,
                       TPM_TIS_STS_COMMAND_CANCEL, sizeof(uint32_t));

    g_assert_false(s.guest_cmd_queued);
    g_assert_cmpuint(s.loc[0].state, ==, TPM_TIS_STATE_READY);
    g_assert_cmpuint(test_cancels, ==, 0);

    tpm_tis_request_completed(&s, 0);
    g_assert_false(s.platform_cmd_active);
    g_assert_null(test_pending);
    g_assert_cmpuint(test_deliveries, ==, 0);
}

static void test_reset_drops_queued_guest(void)
{
    TPMState s;
    TPMBackend be = { };

    setup_state(&s, &be);
    s.guest_cmd_queued = true;
    tpm_tis_reset(&s, false);
    g_assert_false(s.guest_cmd_queued);
}

int main(int argc, char **argv)
{
    int ret;

    g_test_init(&argc, &argv, NULL);
    rust_bql_mock_lock();
    g_test_add_func("/tpm-tis-platform/guest-then-platform",
                    test_guest_then_platform);
    g_test_add_func("/tpm-tis-platform/failure-repeat",
                    test_failure_and_repeat);
    g_test_add_func("/tpm-tis-platform/timeout-owned-queue",
                    test_timeout_owns_buffers_and_queues_guest);
    g_test_add_func("/tpm-tis-platform/effective-response-capacity",
                    test_effective_response_capacity);
    g_test_add_func("/tpm-tis-platform/queued-guest-cancel",
                    test_queued_guest_cancel);
    g_test_add_func("/tpm-tis-platform/reset-drops-queued-guest",
                    test_reset_drops_queued_guest);
    g_test_add_func("/tpm-tis-platform/drtm-enable-guest-access",
                    test_drtm_enable_and_guest_access);
    g_test_add_func("/tpm-tis-platform/without-drtm-unchanged",
                    test_without_drtm_unchanged);
    g_test_add_func("/tpm-tis-platform/drtm-open-atomic",
                    test_drtm_open_is_atomic);
    g_test_add_func("/tpm-tis-platform/drtm-close-activate",
                    test_drtm_close_and_activate);
    g_test_add_func("/tpm-tis-platform/drtm-reset-locality4",
                    test_drtm_reset_and_locality4);
    g_test_add_func("/tpm-tis-platform/drtm-inflight-late-completion",
                    test_drtm_inflight_and_late_completion);
    g_test_add_func("/tpm-tis-platform/drtm-close-reconciles-irq",
                    test_drtm_close_reconciles_irq);
    g_test_add_func("/tpm-tis-platform/drtm-closed-platform-command",
                    test_drtm_closed_platform_command);
    ret = g_test_run();
    return ret;
}
