/*
 * Arm in-process firmware SMCCC registry tests
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/bitops.h"
#include "target/arm/firmware-smc.h"

static void dummy_handler(ARMCPU *cpu, void *opaque)
{
    int *calls = opaque;

    if (calls) {
        (*calls)++;
    }
}

static void assert_rejected(ARMFirmwareSMCRegistry *registry,
                            const ARMFirmwareSMCRoute *route,
                            ARMFirmwareSMCHandler *handler)
{
    Error *err = NULL;

    g_assert_false(arm_firmware_smc_registry_register(
                       registry, route, handler, NULL, &err));
    g_assert_nonnull(err);
    error_free(err);
}

static void test_exact_match(void)
{
    ARMFirmwareSMCRegistry registry;
    int calls = 0;
    ARMFirmwareSMCRoute route = {
        .conduit = ARM_FIRMWARE_SMCCC_CONDUIT_SMC,
        .function_base = 0x84000110,
        .function_mask = BIT_ULL(0) | BIT_ULL(2) | BIT_ULL(63),
    };
    const ARMFirmwareSMCProvider *provider;

    arm_firmware_smc_registry_init(&registry);
    g_assert_true(arm_firmware_smc_registry_register(
                      &registry, &route, dummy_handler, &calls, &error_abort));

    provider = arm_firmware_smc_registry_lookup(
        &registry, ARM_FIRMWARE_SMCCC_CONDUIT_SMC, 0x84000110);
    g_assert_nonnull(provider);
    g_assert_true(provider->handler == dummy_handler);
    g_assert_true(provider->opaque == &calls);
    provider->handler(NULL, provider->opaque);
    g_assert_cmpint(calls, ==, 1);
    g_assert_nonnull(arm_firmware_smc_registry_lookup(
        &registry, ARM_FIRMWARE_SMCCC_CONDUIT_SMC, 0x84000112));
    g_assert_nonnull(arm_firmware_smc_registry_lookup(
        &registry, ARM_FIRMWARE_SMCCC_CONDUIT_SMC, 0x8400014f));
    g_assert_null(arm_firmware_smc_registry_lookup(
        &registry, ARM_FIRMWARE_SMCCC_CONDUIT_SMC, 0x8400010f));
    g_assert_null(arm_firmware_smc_registry_lookup(
        &registry, ARM_FIRMWARE_SMCCC_CONDUIT_SMC, 0x84000111));
    g_assert_null(arm_firmware_smc_registry_lookup(
        &registry, ARM_FIRMWARE_SMCCC_CONDUIT_SMC, 0x84000150));
    g_assert_null(arm_firmware_smc_registry_lookup(
        &registry, ARM_FIRMWARE_SMCCC_CONDUIT_HVC, 0x84000110));

    /* Registration copied the route rather than retaining caller storage. */
    route.function_mask = 0;
    g_assert_nonnull(arm_firmware_smc_registry_lookup(
        &registry, ARM_FIRMWARE_SMCCC_CONDUIT_SMC, 0x84000110));
    route.function_mask = BIT_ULL(0) | BIT_ULL(2) | BIT_ULL(63);
    g_assert_false(arm_firmware_smc_registry_unregister(
                       &registry, &route, dummy_handler, NULL));
    g_assert_true(arm_firmware_smc_registry_unregister(
                      &registry, &route, dummy_handler, &calls));
    g_assert_null(arm_firmware_smc_registry_lookup(
        &registry, ARM_FIRMWARE_SMCCC_CONDUIT_SMC, 0x84000110));
    g_assert_false(arm_firmware_smc_registry_unregister(
                       &registry, &route, dummy_handler, &calls));
    arm_firmware_smc_registry_destroy(&registry);
}

static void test_validation(void)
{
    ARMFirmwareSMCRegistry registry;
    ARMFirmwareSMCRoute route = {
        .conduit = ARM_FIRMWARE_SMCCC_CONDUIT_SMC,
        .function_base = 0x100,
        .function_mask = 1,
    };

    arm_firmware_smc_registry_init(&registry);
    assert_rejected(&registry, NULL, dummy_handler);
    assert_rejected(&registry, &route, NULL);

    route.function_mask = 0;
    assert_rejected(&registry, &route, dummy_handler);
    route.function_mask = BIT_ULL(63);
    route.function_base = UINT32_MAX - 62;
    assert_rejected(&registry, &route, dummy_handler);
    route.function_base = 0x100;
    route.conduit = 0;
    assert_rejected(&registry, &route, dummy_handler);

    arm_firmware_smc_registry_destroy(&registry);
}

static void test_overlap_and_freeze(void)
{
    ARMFirmwareSMCRegistry registry;
    ARMFirmwareSMCRoute first = {
        .conduit = ARM_FIRMWARE_SMCCC_CONDUIT_SMC,
        .function_base = 0x100,
        .function_mask = BIT_ULL(1) | BIT_ULL(4),
    };
    ARMFirmwareSMCRoute hole = {
        .conduit = ARM_FIRMWARE_SMCCC_CONDUIT_SMC,
        .function_base = 0x102,
        .function_mask = BIT_ULL(0),
    };
    ARMFirmwareSMCRoute overlap = {
        .conduit = ARM_FIRMWARE_SMCCC_CONDUIT_SMC,
        .function_base = 0x103,
        .function_mask = BIT_ULL(1),
    };

    arm_firmware_smc_registry_init(&registry);
    g_assert_true(arm_firmware_smc_registry_register(
                      &registry, &first, dummy_handler, NULL, &error_abort));
    g_assert_true(arm_firmware_smc_registry_register(
                      &registry, &hole, dummy_handler, NULL, &error_abort));
    assert_rejected(&registry, &overlap, dummy_handler);

    overlap.conduit = ARM_FIRMWARE_SMCCC_CONDUIT_HVC;
    g_assert_true(arm_firmware_smc_registry_register(
                      &registry, &overlap, dummy_handler, NULL, &error_abort));

    arm_firmware_smc_registry_freeze(&registry);
    overlap.function_base = 0x200;
    assert_rejected(&registry, &overlap, dummy_handler);
    arm_firmware_smc_registry_destroy(&registry);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/arm/firmware-smc/exact-match", test_exact_match);
    g_test_add_func("/arm/firmware-smc/validation", test_validation);
    g_test_add_func("/arm/firmware-smc/overlap-freeze",
                    test_overlap_and_freeze);
    return g_test_run();
}
