/*
 * Arm virt DRTM feature-query construction
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "virt-drtm-features-internal.h"
#include "virt-drtm-smc-internal.h"

#define DRTM_FEATURE_RESPONSE_REGISTERS 1
#define DRTM_REGION_TABLE_HEADER_SIZE   8
#define DRTM_REGION_DESCRIPTOR_SIZE     16
#define DRTM_TCB_TABLE_HEADER_SIZE      8
#define DRTM_TCB_ENTRY_ID_SIZE          4

static VirtDRTMFeaturesResult not_supported(void)
{
    return (VirtDRTMFeaturesResult) { .x0 = VIRT_DRTM_NOT_SUPPORTED };
}

void virt_drtm_features_capabilities(VirtDRTMCapabilities *capabilities,
                                     uint32_t *supported_launch_features)
{
    g_assert(capabilities);
    g_assert(supported_launch_features);

    *capabilities = (VirtDRTMCapabilities) {
        .memory_protection_mask = BIT(0),
        .pcr_schema_mask = BIT(0),
        .maximum_protected_regions = 0,
        /* Variable payloads are checked against the remaining region. */
        .minimum_dlme_data_pages = 1,
        .disable_secure_interrupts = true,
    };
    *supported_launch_features = BIT(7);
}

#ifdef CONFIG_TPM
static bool implemented_function(uint32_t function)
{
    switch (function) {
    case DRTM_VERSION:
    case DRTM_FEATURES:
    case DRTM_UNPROTECT_MEMORY:
    case DRTM_DYNAMIC_LAUNCH:
    case DRTM_CLOSE_LOCALITY:
    case DRTM_GET_ERROR:
    case DRTM_SET_ERROR:
    case DRTM_SET_TCB_HASH:
    case DRTM_LOCK_TCB_HASHES:
    case DRTM_ENABLE_SECURE_INTERRUPTS:
        return true;
    default:
        return false;
    }
}

static size_t digest_size(uint16_t algorithm)
{
    switch (algorithm) {
    case 0x000b:
        return 32;
    case 0x000c:
        return 48;
    case 0x000d:
        return 64;
    default:
        return 0;
    }
}

static size_t pcr_digest_size(uint16_t algorithm)
{
    return algorithm == 0x0004 ? 20 : digest_size(algorithm);
}

static bool add_product(size_t *total, size_t count, size_t item_size)
{
    if (count > (SIZE_MAX - *total) / item_size) {
        return false;
    }
    *total += count * item_size;
    return true;
}

static bool tpm_metadata_valid(const VirtDRTMState *s)
{
    bool selected_active = false;

    if (!s->tpm_ready ||
        s->active_bank_count > ARRAY_SIZE(s->active_banks)) {
        return false;
    }
    for (size_t i = 0; i < s->active_bank_count; i++) {
        if (!pcr_digest_size(s->active_banks[i])) {
            return false;
        }
        selected_active |= s->active_banks[i] ==
                           s->firmware_hash_algorithm;
        for (size_t j = 0; j < i; j++) {
            if (s->active_banks[j] == s->active_banks[i]) {
                return false;
            }
        }
    }
    return selected_active &&
           s->firmware_hash_algorithm == s->tcb_hashes.algorithm;
}

static bool minimum_data_pages(const VirtDRTMState *s,
                               const VirtDRTMCapabilities *capabilities,
                               size_t address_map_capacity,
                               uint32_t *pages)
{
    size_t digest = digest_size(s->firmware_hash_algorithm);
    size_t total = VIRT_DRTM_DATA_HEADER_SIZE +
                   2 * DRTM_REGION_TABLE_HEADER_SIZE +
                   DRTM_TCB_TABLE_HEADER_SIZE +
                   DRTM_REGION_DESCRIPTOR_SIZE;
    /*
     * Exact maximum for the production single-stage profile.  It supplies no
     * TZFW components and has no secondary DCE; the eleventh event is the
     * optional Secure-interrupt-disable event.  Account for fixed headers and
     * the complete-protection sentinel (16), event data (288), per-bank
     * metadata (6 each), every bank's DCE digest, and eleven
     * selected-algorithm digests.  The sentinel is present even though the
     * complete-only profile advertises zero individually protected regions.
     */
    size_t event_log_size = 288 + 6 * s->active_bank_count + 11 * digest;
    size_t page_count;

    for (size_t i = 0; i < s->active_bank_count; i++) {
        size_t bank_digest = pcr_digest_size(s->active_banks[i]);

        if (!bank_digest || bank_digest > SIZE_MAX - event_log_size) {
            return false;
        }
        event_log_size += bank_digest;
    }
    if (!address_map_capacity || !digest || event_log_size > SIZE_MAX - total) {
        return false;
    }
    total += event_log_size;
    if (!add_product(&total, capabilities->maximum_protected_regions,
                     DRTM_REGION_DESCRIPTOR_SIZE) ||
        !add_product(&total, address_map_capacity,
                     DRTM_REGION_DESCRIPTOR_SIZE) ||
        !add_product(&total, VIRT_DRTM_TCB_HASH_CAPACITY,
                     DRTM_TCB_ENTRY_ID_SIZE + digest) ||
        total > SIZE_MAX - (VIRT_DRTM_PAGE_SIZE - 1)) {
        return false;
    }
    page_count = DIV_ROUND_UP(total, VIRT_DRTM_PAGE_SIZE);
    if (page_count > UINT32_MAX) {
        return false;
    }
    *pages = page_count;
    return true;
}
#endif

bool virt_drtm_features_launch_capabilities(
    const VirtDRTMState *s, size_t address_map_capacity,
    VirtDRTMCapabilities *capabilities, uint32_t *supported_launch_features)
{
#ifdef CONFIG_TPM
    uint32_t minimum_pages;

    g_assert(s);
    virt_drtm_features_capabilities(capabilities,
                                    supported_launch_features);
    if (!minimum_data_pages(s, capabilities, address_map_capacity,
                            &minimum_pages)) {
        return false;
    }
    capabilities->minimum_dlme_data_pages = minimum_pages;
    return true;
#else
    (void)s;
    (void)address_map_capacity;
    (void)capabilities;
    (void)supported_launch_features;
    return false;
#endif
}

VirtDRTMFeaturesResult virt_drtm_features_query(const VirtDRTMState *s,
                                                uint64_t boot_pe_id,
                                                size_t address_map_capacity,
                                                uint64_t query)
{
#ifdef CONFIG_TPM
    VirtDRTMCapabilities capabilities;
    VirtDRTMFeaturesResult result = {
        .x0 = DRTM_FEATURE_RESPONSE_REGISTERS,
        .has_x1 = true,
    };
    uint32_t supported_launch_features;
    uint32_t minimum_pages;
    uint8_t feature;

    g_assert(s);
    /* Function availability is fixed once the service is published. */
    if (!(query & VIRT_DRTM_FEATURE_QUERY_FLAG)) {
        if (query >> 32 || !implemented_function(query)) {
            return not_supported();
        }
        return (VirtDRTMFeaturesResult) { .x0 = 0 };
    }
    if (query & MAKE_64BIT_MASK(8, 55)) {
        return not_supported();
    }
    feature = query;
    virt_drtm_features_capabilities(&capabilities,
                                    &supported_launch_features);
    if ((feature == VIRT_DRTM_FEATURE_TPM ||
         feature == VIRT_DRTM_FEATURE_MINIMUM_MEMORY) &&
        !tpm_metadata_valid(s)) {
        return not_supported();
    }
    if (feature == VIRT_DRTM_FEATURE_MINIMUM_MEMORY &&
        !virt_drtm_features_launch_capabilities(
            s, address_map_capacity, &capabilities,
            &supported_launch_features)) {
        return not_supported();
    }
    switch (feature) {
    case VIRT_DRTM_FEATURE_TPM:
        /*
         * Bit 32 denotes TPM2_PCR_Event hashing.  This profile hashes in
         * software and uses PCR_Extend, so TPM presence does not set it.
         */
        result.x1 = (uint64_t)capabilities.pcr_schema_mask << 33 |
                    s->firmware_hash_algorithm;
        break;
    case VIRT_DRTM_FEATURE_MINIMUM_MEMORY:
        minimum_pages = capabilities.minimum_dlme_data_pages;
        result.x1 = (uint64_t)capabilities.minimum_dce_pages << 32 |
                    minimum_pages;
        break;
    case VIRT_DRTM_FEATURE_DMA_PROTECTION:
        result.x1 = (uint64_t)capabilities.maximum_protected_regions << 8 |
                    capabilities.memory_protection_mask;
        break;
    case VIRT_DRTM_FEATURE_BOOT_PE:
        result.x1 = boot_pe_id;
        break;
    case VIRT_DRTM_FEATURE_TCB_HASH:
        result.x1 = VIRT_DRTM_TCB_HASH_CAPACITY;
        break;
    case VIRT_DRTM_FEATURE_IMAGE_AUTHENTICATION:
        result.x1 = capabilities.image_authentication;
        break;
    default:
        return not_supported();
    }
    return result;
#else
    (void)s;
    (void)boot_pe_id;
    (void)address_map_capacity;
    (void)query;
    return not_supported();
#endif
}
