/*
 * Arm virt DRTM feature-query tests
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "../../hw/arm/virt-drtm-features-internal.h"
#include "../../hw/arm/virt-drtm-smc-internal.h"

#define FEATURE(id) (VIRT_DRTM_FEATURE_QUERY_FLAG | (id))
#define BOOT_PE_ID UINT64_C(0x0000000200030405)
#define MAP_CAPACITY 100

static VirtDRTMState state;

static void reset_state(uint16_t algorithm)
{
    memset(&state, 0, sizeof(state));
    state.tpm_ready = true;
    state.active_banks[0] = algorithm;
    state.active_bank_count = 1;
    state.firmware_hash_algorithm = algorithm;
    state.tcb_hashes.algorithm = algorithm;
    state.tcb_hashes.capacity = VIRT_DRTM_TCB_HASH_CAPACITY;
}

static VirtDRTMFeaturesResult query(uint64_t value)
{
    return virt_drtm_features_query(&state, BOOT_PE_ID, MAP_CAPACITY,
                                    value);
}

static void assert_unsupported(uint64_t value)
{
    VirtDRTMFeaturesResult result = query(value);

    g_assert_cmpint(result.x0, ==, VIRT_DRTM_NOT_SUPPORTED);
    g_assert_false(result.has_x1);
}

static void test_function_queries(void)
{
    static const uint32_t functions[] = {
        DRTM_VERSION, DRTM_FEATURES, DRTM_UNPROTECT_MEMORY,
        DRTM_DYNAMIC_LAUNCH, DRTM_CLOSE_LOCALITY, DRTM_GET_ERROR,
        DRTM_SET_ERROR, DRTM_SET_TCB_HASH, DRTM_LOCK_TCB_HASHES,
        DRTM_ENABLE_SECURE_INTERRUPTS,
    };

    reset_state(0x000c);
    for (size_t i = 0; i < ARRAY_SIZE(functions); i++) {
        VirtDRTMFeaturesResult result = query(functions[i]);

        g_assert_cmpint(result.x0, ==, 0);
        g_assert_false(result.has_x1);
    }

    for (uint32_t function = DRTM_FID_BASE;
         function <= DRTM_FID_BASE + 0x1f; function++) {
        bool implemented = false;

        for (size_t i = 0; i < ARRAY_SIZE(functions); i++) {
            implemented |= function == functions[i];
        }
        if (!implemented) {
            assert_unsupported(function);
        }
    }
    assert_unsupported(0x84000110);
    for (unsigned int bit = 32; bit <= 62; bit++) {
        assert_unsupported((UINT64_C(1) << bit) | DRTM_VERSION);
    }
}

static void test_feature_queries(void)
{
    VirtDRTMFeaturesResult result;

    reset_state(0x000c);
    result = query(FEATURE(VIRT_DRTM_FEATURE_TPM));
    g_assert_cmpint(result.x0, ==, 1);
    g_assert_true(result.has_x1);
    g_assert_cmphex(result.x1, ==, (UINT64_C(1) << 33) | 0x000c);
    g_assert_cmphex(result.x1 & (UINT64_C(1) << 32), ==, 0);

    result = query(FEATURE(VIRT_DRTM_FEATURE_MINIMUM_MEMORY));
    g_assert_cmpint(result.x0, ==, 1);
    /* SHA-384, 100 map entries, 64 caller hashes: at most 5902 bytes. */
    g_assert_cmphex(result.x1, ==, 2);

    result = query(FEATURE(VIRT_DRTM_FEATURE_DMA_PROTECTION));
    g_assert_cmphex(result.x1, ==, 1);
    result = query(FEATURE(VIRT_DRTM_FEATURE_BOOT_PE));
    g_assert_cmphex(result.x1, ==, BOOT_PE_ID);
    result = query(FEATURE(VIRT_DRTM_FEATURE_TCB_HASH));
    g_assert_cmphex(result.x1, ==, VIRT_DRTM_TCB_HASH_CAPACITY);
    result = query(FEATURE(VIRT_DRTM_FEATURE_IMAGE_AUTHENTICATION));
    g_assert_cmphex(result.x1, ==, 0);
    g_assert_cmpint(result.x0, ==, 1);
    g_assert_true(result.has_x1);
}

static void test_algorithm_and_size_are_live(void)
{
    VirtDRTMFeaturesResult result;

    reset_state(0x000d);
    result = query(FEATURE(VIRT_DRTM_FEATURE_TPM));
    g_assert_cmphex(result.x1, ==, (UINT64_C(1) << 33) | 0x000d);
    result = query(FEATURE(VIRT_DRTM_FEATURE_MINIMUM_MEMORY));
    /* SHA-512 increases the maximum payload to 7118 bytes. */
    g_assert_cmphex(result.x1, ==, 2);
    result = query(FEATURE(VIRT_DRTM_FEATURE_TCB_HASH));
    g_assert_cmphex(result.x1, ==, VIRT_DRTM_TCB_HASH_CAPACITY);

    state.tpm_ready = false;
    assert_unsupported(FEATURE(VIRT_DRTM_FEATURE_TPM));
    memset(state.active_banks, 0, sizeof(state.active_banks));
    state.active_bank_count = 0;
    state.firmware_hash_algorithm = 0;
    state.tcb_hashes.algorithm = 0;
    assert_unsupported(FEATURE(VIRT_DRTM_FEATURE_MINIMUM_MEMORY));
    result = query(FEATURE(VIRT_DRTM_FEATURE_DMA_PROTECTION));
    g_assert_cmphex(result.x1, ==, 1);
    result = query(FEATURE(VIRT_DRTM_FEATURE_BOOT_PE));
    g_assert_cmphex(result.x1, ==, BOOT_PE_ID);
    result = query(FEATURE(VIRT_DRTM_FEATURE_TCB_HASH));
    g_assert_cmphex(result.x1, ==, VIRT_DRTM_TCB_HASH_CAPACITY);
    result = query(FEATURE(VIRT_DRTM_FEATURE_IMAGE_AUTHENTICATION));
    g_assert_cmpint(result.x0, ==, 1);
    g_assert_true(result.has_x1);
    g_assert_cmphex(result.x1, ==, 0);
    assert_unsupported(FEATURE(VIRT_DRTM_FEATURE_TPM));
    state.tpm_ready = true;
    reset_state(0x000d);
    state.tcb_hashes.algorithm = 0x000b;
    assert_unsupported(FEATURE(VIRT_DRTM_FEATURE_TPM));
    result = virt_drtm_features_query(&state, BOOT_PE_ID, SIZE_MAX,
                                      DRTM_DYNAMIC_LAUNCH);
    g_assert_cmpint(result.x0, ==, 0);

    reset_state(0x000b);
    result = virt_drtm_features_query(
        &state, BOOT_PE_ID, SIZE_MAX,
        FEATURE(VIRT_DRTM_FEATURE_MINIMUM_MEMORY));
    g_assert_cmpint(result.x0, ==, VIRT_DRTM_NOT_SUPPORTED);
    g_assert_false(result.has_x1);
}

static void test_invalid_feature_queries(void)
{
    reset_state(0x000b);
    for (unsigned int feature = 0; feature <= UINT8_MAX; feature++) {
        if (feature < VIRT_DRTM_FEATURE_TPM ||
            feature > VIRT_DRTM_FEATURE_IMAGE_AUTHENTICATION) {
            assert_unsupported(FEATURE(feature));
        }
    }
    for (unsigned int bit = 8; bit <= 62; bit++) {
        assert_unsupported(FEATURE(VIRT_DRTM_FEATURE_TPM) |
                           (UINT64_C(1) << bit));
    }
}

static void test_stable_launch_minimum(void)
{
    VirtDRTMCapabilities capabilities;
    VirtDRTMFeaturesResult result;
    uint32_t supported_features;

    reset_state(0x000b);
    g_assert_true(virt_drtm_features_launch_capabilities(
        &state, VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &capabilities,
        &supported_features));
    g_assert_cmphex(capabilities.memory_protection_mask, ==, 1);
    g_assert_cmpuint(capabilities.maximum_protected_regions, ==, 0);
    g_assert_cmphex(supported_features, ==, 1U << 7);
    result = virt_drtm_features_query(
        &state, BOOT_PE_ID, VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS,
        FEATURE(VIRT_DRTM_FEATURE_MINIMUM_MEMORY));
    g_assert_cmpint(result.x0, ==, 1);
    g_assert_cmpuint(result.x1, ==, 17);
    g_assert_cmpuint(capabilities.minimum_dlme_data_pages, ==, result.x1);
}

static void test_complete_sentinel_crosses_page_boundary(void)
{
    VirtDRTMCapabilities capabilities;
    uint32_t supported_features;

    reset_state(0x000b);
    /*
     * The fixed SHA-256 payload is 3086 bytes, including the mandatory
     * 16-byte complete-protection sentinel.  Exactly 63 map entries fit in
     * one page; the next descriptor crosses the boundary.
     */
    g_assert_true(virt_drtm_features_launch_capabilities(
        &state, 63, &capabilities, &supported_features));
    g_assert_cmpuint(capabilities.minimum_dlme_data_pages, ==, 1);
    g_assert_true(virt_drtm_features_launch_capabilities(
        &state, 64, &capabilities, &supported_features));
    g_assert_cmpuint(capabilities.maximum_protected_regions, ==, 0);
    g_assert_cmpuint(capabilities.minimum_dlme_data_pages, ==, 2);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/virt-drtm/features/functions", test_function_queries);
    g_test_add_func("/virt-drtm/features/values", test_feature_queries);
    g_test_add_func("/virt-drtm/features/live",
                    test_algorithm_and_size_are_live);
    g_test_add_func("/virt-drtm/features/invalid",
                    test_invalid_feature_queries);
    g_test_add_func("/virt-drtm/features/stable-launch-minimum",
                    test_stable_launch_minimum);
    g_test_add_func("/virt-drtm/features/complete-sentinel-boundary",
                    test_complete_sentinel_crosses_page_boundary);
    return g_test_run();
}
