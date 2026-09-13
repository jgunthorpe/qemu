/*
 * Arm virt DRTM SMC dispatch tests
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qapi/error.h"
#include "hw/arm/virt-drtm.h"
#include "../../hw/arm/virt-drtm-smc-internal.h"

#define TEST_GPA UINT64_C(0x100000)

typedef struct TestContext {
    VirtDRTMState *service;
    uint8_t guest[256];
    unsigned int reads;
    unsigned int fail_read;
    uint64_t ram_size;
    unsigned int close_calls;
    TPMDRTMLocalityCloseResult close_result;
    bool close_transport;
    bool reset_requested;
    unsigned int feature_calls;
    uint64_t feature_query;
    VirtDRTMFeaturesResult feature_result;
    unsigned int ready_calls;
    unsigned int ready_failures;
    unsigned int launch_calls;
    uint64_t launch_address;
    VirtDRTMLaunchResult launch_result;
} TestContext;

static bool guest_is_ram(void *opaque, uint64_t address, uint64_t size)
{
    TestContext *ctx = opaque;

    return address >= TEST_GPA && size <= ctx->ram_size &&
           address - TEST_GPA <= ctx->ram_size - size;
}

static void state_init(VirtDRTMState *s)
{
    memset(s, 0, sizeof(*s));
    virt_drtm_workflow_init(&s->workflow);
    g_assert_true(virt_drtm_tcb_init(&s->tcb_hashes, 0x000b, 4));
    s->tpm_ready = true;
}

static bool ensure_ready(void *opaque, Error **errp)
{
    TestContext *ctx = opaque;

    ctx->ready_calls++;
    if (ctx->ready_calls <= ctx->ready_failures) {
        error_setg(errp, "TPM has not completed startup");
        return false;
    }
    ctx->service->tpm_ready = true;
    return true;
}

static bool read_guest(void *opaque, uint64_t address, void *data, size_t size)
{
    TestContext *ctx = opaque;
    uint64_t offset;

    ctx->reads++;
    if (ctx->reads == ctx->fail_read || address < TEST_GPA) {
        return false;
    }
    offset = address - TEST_GPA;
    if (offset > sizeof(ctx->guest) || size > sizeof(ctx->guest) - offset) {
        return false;
    }
    memcpy(data, ctx->guest + offset, size);
    return true;
}

static bool close_locality(void *opaque, uint8_t locality,
                           TPMDRTMLocalityCloseResult *result, Error **errp)
{
    TestContext *ctx = opaque;

    ctx->close_calls++;
    *result = ctx->close_result;
    return ctx->close_transport;
}

static void request_reset(void *opaque)
{
    TestContext *ctx = opaque;

    ctx->reset_requested = true;
}

static VirtDRTMFeaturesResult features(void *opaque, uint64_t query)
{
    TestContext *ctx = opaque;

    ctx->feature_calls++;
    ctx->feature_query = query;
    return ctx->feature_result;
}

static VirtDRTMLaunchResult dynamic_launch(void *opaque, uint64_t address,
                                           Error **errp)
{
    TestContext *ctx = opaque;

    ctx->launch_calls++;
    ctx->launch_address = address;
    return ctx->launch_result;
}

static const VirtDRTMSMCOps ops = {
    .ensure_ready = ensure_ready,
    .guest_is_ram = guest_is_ram,
    .read_guest = read_guest,
    .close_locality = close_locality,
    .request_cold_reset = request_reset,
    .features = features,
    .dynamic_launch = dynamic_launch,
};

static void test_tpm_readiness_retry(void)
{
    VirtDRTMState s;
    TestContext ctx = { .ready_failures = 1 };
    VirtDRTMSMCResult r;
    Error *err = NULL;

    state_init(&s);
    s.tpm_ready = false;
    ctx.service = &s;

    /* VERSION and function availability never depend on TPM runtime state. */
    r = virt_drtm_smc_dispatch_with_ops(&s, true, DRTM_VERSION, 0,
                                        &ops, &ctx, &error_abort);
    g_assert_cmphex(r.status, ==, (1U << 16) | 4U);
    r = virt_drtm_smc_dispatch_with_ops(&s, true, DRTM_FEATURES,
                                        DRTM_DYNAMIC_LAUNCH,
                                        &ops, &ctx, &error_abort);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_SUCCESS);
    g_assert_cmpuint(ctx.ready_calls, ==, 0);
    ctx.feature_result = (VirtDRTMFeaturesResult) {
        .x0 = 1, .has_x1 = true, .x1 = UINT64_C(0x0000000100020304),
    };
    r = virt_drtm_smc_dispatch_with_ops(
        &s, true, DRTM_FEATURES,
        VIRT_DRTM_FEATURE_QUERY_FLAG | VIRT_DRTM_FEATURE_BOOT_PE,
        &ops, &ctx, &error_abort);
    g_assert_cmpint(r.status, ==, 1);
    g_assert_true(r.has_x1);
    g_assert_cmphex(r.x1, ==, UINT64_C(0x0000000100020304));
    g_assert_cmpuint(ctx.ready_calls, ==, 0);
    g_assert_cmpuint(ctx.feature_calls, ==, 2);
    g_assert_cmphex(ctx.feature_query, ==,
                    VIRT_DRTM_FEATURE_QUERY_FLAG |
                    VIRT_DRTM_FEATURE_BOOT_PE);

    ctx.feature_result.x1 = VIRT_DRTM_TCB_HASH_CAPACITY;
    r = virt_drtm_smc_dispatch_with_ops(
        &s, true, DRTM_FEATURES,
        VIRT_DRTM_FEATURE_QUERY_FLAG | VIRT_DRTM_FEATURE_TCB_HASH,
        &ops, &ctx, &error_abort);
    g_assert_cmpint(r.status, ==, 1);
    g_assert_true(r.has_x1);
    g_assert_cmphex(r.x1, ==, VIRT_DRTM_TCB_HASH_CAPACITY);
    g_assert_cmpuint(ctx.ready_calls, ==, 0);

    ctx.feature_result.x1 = UINT64_C(0x4003);
    r = virt_drtm_smc_dispatch_with_ops(
        &s, true, DRTM_FEATURES,
        VIRT_DRTM_FEATURE_QUERY_FLAG | VIRT_DRTM_FEATURE_DMA_PROTECTION,
        &ops, &ctx, &error_abort);
    g_assert_cmpint(r.status, ==, 1);
    g_assert_cmphex(r.x1, ==, UINT64_C(0x4003));
    g_assert_cmpuint(ctx.ready_calls, ==, 0);

    ctx.feature_result.x1 = 0;
    r = virt_drtm_smc_dispatch_with_ops(
        &s, true, DRTM_FEATURES,
        VIRT_DRTM_FEATURE_QUERY_FLAG |
        VIRT_DRTM_FEATURE_IMAGE_AUTHENTICATION,
        &ops, &ctx, &error_abort);
    g_assert_cmpint(r.status, ==, 1);
    g_assert_true(r.has_x1);
    g_assert_cmphex(r.x1, ==, 0);
    g_assert_cmpuint(ctx.ready_calls, ==, 0);

    ctx.feature_result = (VirtDRTMFeaturesResult) {
        .x0 = VIRT_DRTM_NOT_SUPPORTED,
    };
    r = virt_drtm_smc_dispatch_with_ops(
        &s, true, DRTM_FEATURES,
        VIRT_DRTM_FEATURE_QUERY_FLAG | (UINT64_C(1) << 8) |
        VIRT_DRTM_FEATURE_TPM,
        &ops, &ctx, &error_abort);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_NOT_SUPPORTED);
    g_assert_cmpuint(ctx.ready_calls, ==, 0);

    ctx.feature_result = (VirtDRTMFeaturesResult) {
        .x0 = 1, .has_x1 = true, .x1 = 0x1234,
    };
    r = virt_drtm_smc_dispatch_with_ops(
        &s, true, DRTM_FEATURES,
        VIRT_DRTM_FEATURE_QUERY_FLAG | VIRT_DRTM_FEATURE_TPM,
        &ops, &ctx, &err);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_TPM_ERROR);
    g_assert_nonnull(err);
    error_free(err);
    err = NULL;
    g_assert_false(s.tpm_ready);

    r = virt_drtm_smc_dispatch_with_ops(
        &s, true, DRTM_FEATURES,
        VIRT_DRTM_FEATURE_QUERY_FLAG | VIRT_DRTM_FEATURE_TPM,
        &ops, &ctx, &error_abort);
    g_assert_cmpint(r.status, ==, 1);
    g_assert_cmphex(r.x1, ==, 0x1234);
    g_assert_cmpuint(ctx.ready_calls, ==, 2);
    g_assert_true(s.tpm_ready);

    s.tpm_ready = false;
    ctx.ready_failures = 3;
    r = virt_drtm_smc_dispatch_with_ops(
        &s, true, DRTM_DYNAMIC_LAUNCH, TEST_GPA,
        &ops, &ctx, &err);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_TPM_ERROR);
    g_assert_nonnull(err);
    error_free(err);
    err = NULL;
    g_assert_cmpuint(ctx.launch_calls, ==, 0);

    ctx.ready_failures = 4;
    r = virt_drtm_smc_dispatch_with_ops(
        &s, true, DRTM_LOCK_TCB_HASHES, 0, &ops, &ctx, &err);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_TPM_ERROR);
    g_assert_nonnull(err);
    error_free(err);
    err = NULL;
    g_assert_false(s.tcb_hashes.locked);
    r = virt_drtm_smc_dispatch_with_ops(
        &s, true, DRTM_LOCK_TCB_HASHES, 0, &ops, &ctx, &error_abort);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_SUCCESS);
    g_assert_true(s.tcb_hashes.locked);
    g_assert_cmpuint(ctx.ready_calls, ==, 5);

    /* AArch32 dispatch remains rejected without touching TPM readiness. */
    r = virt_drtm_smc_dispatch_with_ops(
        &s, false, DRTM_DYNAMIC_LAUNCH, TEST_GPA,
        &ops, &ctx, &error_abort);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_DENIED);
    g_assert_cmpuint(ctx.ready_calls, ==, 5);
}

static VirtDRTMSMCResult dispatch(VirtDRTMState *s, TestContext *ctx,
                                  uint32_t fid, uint64_t x1)
{
    return virt_drtm_smc_dispatch_with_ops(s, true, fid, x1, &ops, ctx,
                                           &error_abort);
}

static void make_tcb_table(TestContext *ctx, unsigned int count)
{
    ctx->ram_size = sizeof(ctx->guest);
    stw_le_p(ctx->guest, 1);
    stw_le_p(ctx->guest + 2, count);
    stw_le_p(ctx->guest + 4, 0x000b);
    stw_le_p(ctx->guest + 6, 0);
    for (unsigned int i = 0; i < count; i++) {
        size_t offset = 8 + i * 36;

        stl_le_p(ctx->guest + offset, 0x80000041 + i);
        memset(ctx->guest + offset + 4, i + 1, 32);
    }
}

static void test_publication_and_width(void)
{
    VirtDRTMState s;
    TestContext ctx = {
        .feature_result = { .x0 = 1, .has_x1 = true, .x1 = 0x1234 },
        .launch_result = {
            .result = VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS,
            .stage = VIRT_DRTM_LAUNCH_PROBE,
        },
    };
    VirtDRTMSMCResult r;

    state_init(&s);
    r = dispatch(&s, &ctx, DRTM_VERSION, 0);
    g_assert_cmphex(r.status, ==, (1U << 16) | 4U);
    g_assert_false(r.has_x1);
    r = dispatch(&s, &ctx, DRTM_FEATURES, UINT64_C(0x8000000000000001));
    g_assert_cmpint(r.status, ==, 1);
    g_assert_true(r.has_x1);
    g_assert_cmphex(r.x1, ==, 0x1234);
    g_assert_cmpuint(ctx.feature_calls, ==, 1);
    g_assert_cmphex(ctx.feature_query, ==, UINT64_C(0x8000000000000001));
    r = dispatch(&s, &ctx, DRTM_DYNAMIC_LAUNCH, TEST_GPA);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    g_assert_false(r.non_returning);
    g_assert_cmpuint(ctx.launch_calls, ==, 1);
    g_assert_cmphex(ctx.launch_address, ==, TEST_GPA);

    ctx.launch_result = (VirtDRTMLaunchResult) {
        .result = VIRT_DRTM_TPM_ERROR,
        .stage = VIRT_DRTM_LAUNCH_EXTEND_DCE,
        .committed = true,
        .reset_requested = true,
        .non_returning = true,
    };
    r = dispatch(&s, &ctx, DRTM_DYNAMIC_LAUNCH, TEST_GPA);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_TPM_ERROR);
    g_assert_true(r.non_returning);
    g_assert_cmpint(r.launch_stage, ==, VIRT_DRTM_LAUNCH_EXTEND_DCE);
    r = virt_drtm_smc_dispatch_with_ops(&s, false, DRTM_GET_ERROR, 0,
                                        &ops, &ctx, &error_abort);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_NOT_SUPPORTED);
    g_assert_false(r.has_x1);
    r = virt_drtm_smc_dispatch_with_ops(
        &s, false, DRTM_DYNAMIC_LAUNCH, TEST_GPA,
        &ops, &ctx, &error_abort);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_DENIED);
    g_assert_cmpuint(ctx.launch_calls, ==, 2);
}

static void test_tcb_set_and_lock(void)
{
    VirtDRTMState s;
    TestContext ctx = { 0 };
    VirtDRTMSMCResult r;

    state_init(&s);
    make_tcb_table(&ctx, 2);
    r = dispatch(&s, &ctx, DRTM_SET_TCB_HASH, TEST_GPA);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_SUCCESS);
    g_assert_true(r.has_x1);
    g_assert_cmpuint(r.x1, ==, 2);
    g_assert_cmpuint(ctx.reads, ==, 3);
    g_assert_cmpuint(s.tcb_hashes.count, ==, 2);
    g_assert_cmphex(s.tcb_hashes.hashes[0].id, ==, 0x41);

    r = dispatch(&s, &ctx, DRTM_LOCK_TCB_HASHES, 0);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_SUCCESS);
    g_assert_false(r.has_x1);
    r = dispatch(&s, &ctx, DRTM_LOCK_TCB_HASHES, 0);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_DENIED);
    r = dispatch(&s, &ctx, DRTM_SET_TCB_HASH, TEST_GPA);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_DENIED);
    g_assert_cmpuint(ctx.reads, ==, 3);
}

static void test_tcb_failure_is_atomic(void)
{
    VirtDRTMState s;
    TestContext ctx = { .fail_read = 3 };
    VirtDRTMSMCResult r;

    state_init(&s);
    make_tcb_table(&ctx, 2);
    r = dispatch(&s, &ctx, DRTM_SET_TCB_HASH, TEST_GPA);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_INVALID_DATA);
    g_assert_true(r.has_x1);
    g_assert_cmpuint(r.x1, ==, 1);
    g_assert_cmpuint(s.tcb_hashes.count, ==, 0);

    ctx.reads = 0;
    ctx.fail_read = 1;
    r = dispatch(&s, &ctx, DRTM_SET_TCB_HASH, TEST_GPA);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    g_assert_false(r.has_x1);
    g_assert_cmpuint(s.tcb_hashes.count, ==, 0);

    ctx.reads = 0;
    ctx.fail_read = 0;
    stw_le_p(ctx.guest + 2, 5);
    r = dispatch(&s, &ctx, DRTM_SET_TCB_HASH, TEST_GPA);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
    g_assert_cmpuint(ctx.reads, ==, 1);

    ctx.reads = 0;
    make_tcb_table(&ctx, 2);
    ctx.ram_size = 8 + 36;
    r = dispatch(&s, &ctx, DRTM_SET_TCB_HASH, TEST_GPA);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    g_assert_false(r.has_x1);
    g_assert_cmpuint(ctx.reads, ==, 1);
    g_assert_cmpuint(s.tcb_hashes.count, ==, 0);

    ctx.reads = 0;
    ctx.ram_size = 0;
    r = dispatch(&s, &ctx, DRTM_SET_TCB_HASH, TEST_GPA);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    g_assert_cmpuint(ctx.reads, ==, 0);
}

static void test_close_locality(void)
{
    VirtDRTMState s;
    TestContext ctx = {
        .close_transport = true,
        .close_result = TPM_DRTM_LOCALITY_NOT_RELINQUISHED,
    };
    VirtDRTMSMCResult r;

    state_init(&s);
    s.workflow.phase = VIRT_DRTM_PHASE_DLME;
    s.workflow.locality[2] = VIRT_DRTM_LOCALITY_ACTIVE;
    r = dispatch(&s, &ctx, DRTM_CLOSE_LOCALITY, 2);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_DENIED);
    g_assert_cmpint(s.workflow.locality[2], ==, VIRT_DRTM_LOCALITY_ACTIVE);

    ctx.close_result = TPM_DRTM_LOCALITY_CLOSED;
    r = dispatch(&s, &ctx, DRTM_CLOSE_LOCALITY, 2);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_SUCCESS);
    g_assert_cmpint(s.workflow.locality[2], ==, VIRT_DRTM_LOCALITY_CLOSED);
    r = dispatch(&s, &ctx, DRTM_CLOSE_LOCALITY, 2);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_ALREADY_CLOSED);
    g_assert_cmpuint(ctx.close_calls, ==, 2);

    r = dispatch(&s, &ctx, DRTM_CLOSE_LOCALITY, 1);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
}

static void test_memory_interrupt_and_errors(void)
{
    VirtDRTMState s;
    TestContext ctx = { 0 };
    VirtDRTMSMCResult r;

    state_init(&s);
    s.workflow.phase = VIRT_DRTM_PHASE_DLME;
    s.workflow.protection = VIRT_DRTM_PROTECTION_REGION;
    s.workflow.protection_release_available = true;
    s.workflow.secure_interrupts = VIRT_DRTM_SECURE_INTERRUPTS_DISABLED;
    r = dispatch(&s, &ctx, DRTM_UNPROTECT_MEMORY, 0);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_SUCCESS);
    g_assert_cmpint(s.workflow.protection, ==, VIRT_DRTM_PROTECTION_NONE);
    r = dispatch(&s, &ctx, DRTM_UNPROTECT_MEMORY, 0);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_DENIED);
    r = dispatch(&s, &ctx, DRTM_ENABLE_SECURE_INTERRUPTS, 0);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_SUCCESS);
    r = dispatch(&s, &ctx, DRTM_ENABLE_SECURE_INTERRUPTS, 0);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_DENIED);

    r = dispatch(&s, &ctx, DRTM_SET_ERROR, UINT64_C(0x123456789abcdef0));
    g_assert_cmpint(r.status, ==, VIRT_DRTM_SUCCESS);
    g_assert_false(ctx.reset_requested);
    g_assert_cmphex(s.workflow.sticky_error,
                    ==, UINT64_C(0x123456789abcdffd));
    r = dispatch(&s, &ctx, DRTM_GET_ERROR, 0);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_SUCCESS);
    g_assert_true(r.has_x1);
    g_assert_cmphex(r.x1, ==, s.workflow.sticky_error);
}

static void test_dce_set_error_requests_reset(void)
{
    VirtDRTMState s;
    TestContext ctx = { 0 };
    VirtDRTMSMCResult r;

    state_init(&s);
    s.workflow.phase = VIRT_DRTM_PHASE_DCE;
    r = dispatch(&s, &ctx, DRTM_SET_ERROR, 2 << 3);
    g_assert_cmpint(r.status, ==, VIRT_DRTM_SUCCESS);
    g_assert_true(ctx.reset_requested);
    g_assert_cmpint(s.workflow.phase, ==, VIRT_DRTM_PHASE_REMEDIATION);
    g_assert_cmphex(s.workflow.sticky_error, ==, (2 << 3) | 4);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/virt-drtm/smc/publication-and-width",
                    test_publication_and_width);
    g_test_add_func("/virt-drtm/smc/tpm-readiness-retry",
                    test_tpm_readiness_retry);
    g_test_add_func("/virt-drtm/smc/tcb-set-and-lock",
                    test_tcb_set_and_lock);
    g_test_add_func("/virt-drtm/smc/tcb-failure-atomic",
                    test_tcb_failure_is_atomic);
    g_test_add_func("/virt-drtm/smc/close-locality", test_close_locality);
    g_test_add_func("/virt-drtm/smc/memory-interrupt-error",
                    test_memory_interrupt_and_errors);
    g_test_add_func("/virt-drtm/smc/dce-error-reset",
                    test_dce_set_error_requests_reset);
    return g_test_run();
}
