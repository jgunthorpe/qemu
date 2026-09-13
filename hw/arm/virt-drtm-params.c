/*
 * Arm DRTM launch parameter decoder
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "hw/arm/virt-drtm-params.h"

#define DRTM_PAGE_SIZE 4096
#define DRTM_TABLE_HEADER_SIZE 8
#define DRTM_REGION_DESCRIPTOR_SIZE 16

typedef struct MutableParameters {
    VirtDRTMParameters public;
    VirtDRTMProtectedRegion regions[];
} MutableParameters;

typedef struct Range {
    uint64_t start;
    uint64_t end;
} Range;

static uint16_t load_le16(const uint8_t *p)
{
    return p[0] | (uint16_t)p[1] << 8;
}

static uint32_t load_le32(const uint8_t *p)
{
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

static uint64_t load_le64(const uint8_t *p)
{
    return load_le32(p) | (uint64_t)load_le32(p + 4) << 32;
}

static bool range_make(uint64_t address, uint64_t size, Range *range)
{
    if (!size || address > UINT64_MAX - size) {
        return false;
    }
    range->start = address;
    range->end = address + size;
    return true;
}

static bool ranges_overlap(Range a, Range b)
{
    return a.start < b.end && b.start < a.end;
}

static bool range_contains(Range outer, Range inner)
{
    return outer.start <= inner.start && inner.end <= outer.end;
}

static bool range_is_ram(VirtDRTMIsRamFn is_ram, void *opaque, Range range)
{
    return is_ram(opaque, range.start, range.end - range.start);
}

static int region_compare(const void *ap, const void *bp)
{
    const VirtDRTMProtectedRegion *a = ap;
    const VirtDRTMProtectedRegion *b = bp;

    return a->address < b->address ? -1 : a->address > b->address;
}

static bool regions_cover(const VirtDRTMProtectedRegion *regions,
                          uint32_t count, Range wanted)
{
    uint64_t cursor = wanted.start;

    for (uint32_t i = 0; i < count && cursor < wanted.end; i++) {
        uint64_t end = regions[i].address + regions[i].size;

        if (end <= cursor) {
            continue;
        }
        if (regions[i].address > cursor) {
            return false;
        }
        cursor = MIN(end, wanted.end);
    }
    return cursor == wanted.end;
}

void virt_drtm_params_free(const VirtDRTMParameters *parameters)
{
    g_free((void *)parameters);
}

VirtDRTMParamStatus virt_drtm_params_decode(
    uint64_t parameters_address, const VirtDRTMCapabilities *capabilities,
    VirtDRTMReadFn read, VirtDRTMIsRamFn is_ram, void *opaque,
    const VirtDRTMParameters **result)
{
    uint8_t raw[VIRT_DRTM_PARAMETERS_SIZE];
    uint32_t features;
    uint8_t memory_protection, pcr_schema;
    uint64_t dlme_address, dlme_size, image_offset, entry_offset;
    uint64_t image_size, data_offset, dce_address, dce_size;
    uint64_t table_address, table_size, expected_size, maximum_table_size = 0;
    Range params, dlme, image, entry, data, dce, table;
    bool has_dce, has_table;
    uint8_t *table_raw = NULL;
    MutableParameters *decoded = NULL;
    uint32_t count = 0;

    g_assert(result);
    *result = NULL;
    if (!capabilities || !read || !is_ram ||
        parameters_address % DRTM_PAGE_SIZE ||
        !range_make(parameters_address, sizeof(raw), &params) ||
        !range_is_ram(is_ram, opaque, params) ||
        !read(opaque, parameters_address, raw, sizeof(raw))) {
        return VIRT_DRTM_INVALID_PARAMETERS;
    }

    if (load_le16(raw) != 2 || load_le16(raw + 2) != 0) {
        return VIRT_DRTM_INVALID_PARAMETERS;
    }

    features = load_le32(raw + 4);
    memory_protection = (features >> 3) & 7;
    pcr_schema = (features >> 1) & 3;
    if (features & ~0xffU || memory_protection > 1 || pcr_schema > 1 ||
        !(capabilities->memory_protection_mask & BIT(memory_protection)) ||
        !(capabilities->pcr_schema_mask & BIT(pcr_schema)) ||
        ((features & BIT(0)) && !capabilities->tpm_hashing) ||
        ((features & BIT(6)) && !capabilities->image_authentication) ||
        ((features & BIT(7)) && !capabilities->disable_secure_interrupts) ||
        (pcr_schema == 1 && !(features & BIT(6)))) {
        return VIRT_DRTM_INVALID_PARAMETERS;
    }

    dlme_address = load_le64(raw + 8);
    dlme_size = load_le64(raw + 16);
    image_offset = load_le64(raw + 24);
    entry_offset = load_le64(raw + 32);
    image_size = load_le64(raw + 40);
    data_offset = load_le64(raw + 48);
    dce_address = load_le64(raw + 56);
    dce_size = load_le64(raw + 64);
    table_address = load_le64(raw + 72);
    table_size = load_le64(raw + 80);

    if (dlme_address % DRTM_PAGE_SIZE ||
        !range_make(dlme_address, dlme_size, &dlme) ||
        !range_is_ram(is_ram, opaque, dlme) ||
        image_offset > UINT64_MAX - dlme_address ||
        !range_make(dlme_address + image_offset, image_size, &image) ||
        !range_contains(dlme, image) || image.start % DRTM_PAGE_SIZE ||
        entry_offset >= image_size || image.start > UINT64_MAX - entry_offset ||
        !range_make(image.start + entry_offset, 1, &entry) ||
        !range_contains(image, entry) ||
        data_offset >= dlme_size || dlme_address > UINT64_MAX - data_offset ||
        !range_make(dlme_address + data_offset, dlme_size - data_offset, &data) ||
        data.start % DRTM_PAGE_SIZE || image.end > data.start ||
        data.end - data.start <
        (uint64_t)capabilities->minimum_dlme_data_pages * DRTM_PAGE_SIZE) {
        return VIRT_DRTM_INVALID_PARAMETERS;
    }

    has_dce = dce_address || dce_size;
    if (has_dce != (capabilities->minimum_dce_pages != 0) ||
        (has_dce && (!dce_address || !dce_size ||
                     dce_address % DRTM_PAGE_SIZE ||
                     !range_make(dce_address, dce_size, &dce) ||
                     !range_is_ram(is_ram, opaque, dce) ||
                     dce_size < (uint64_t)capabilities->minimum_dce_pages *
                                DRTM_PAGE_SIZE))) {
        return VIRT_DRTM_INVALID_PARAMETERS;
    }

    has_table = memory_protection == 1;
    if (has_table) {
        maximum_table_size = DRTM_TABLE_HEADER_SIZE +
            (uint64_t)capabilities->maximum_protected_regions *
            DRTM_REGION_DESCRIPTOR_SIZE;
    }
    if ((!has_table && (table_address || table_size)) ||
        (has_table && (!table_address || !table_size ||
                       table_address % DRTM_PAGE_SIZE))) {
        return VIRT_DRTM_INVALID_PARAMETERS;
    }
    if (has_table && (!capabilities->maximum_protected_regions ||
                      table_size < DRTM_TABLE_HEADER_SIZE ||
                      table_size > maximum_table_size ||
                      (uint64_t)(size_t)table_size != table_size)) {
        return VIRT_DRTM_MEM_PROTECT_INVALID;
    }
    if (has_table && !range_make(table_address, table_size, &table)) {
        return VIRT_DRTM_INVALID_PARAMETERS;
    }
    if (has_table && !range_is_ram(is_ram, opaque, table)) {
        return VIRT_DRTM_MEM_PROTECT_INVALID;
    }

    if ((has_dce && ranges_overlap(dlme, dce)) ||
        (has_table && ranges_overlap(dlme, table)) ||
        (has_dce && has_table && ranges_overlap(dce, table))) {
        return VIRT_DRTM_INVALID_PARAMETERS;
    }

    if (has_table) {
        table_raw = g_try_malloc(table_size);
        if (!table_raw) {
            return VIRT_DRTM_OUT_OF_RESOURCE;
        }
        if (!read(opaque, table_address, table_raw, table_size)) {
            g_free(table_raw);
            return VIRT_DRTM_MEM_PROTECT_INVALID;
        }
        if (load_le16(table_raw) != 1 || load_le16(table_raw + 2) != 0) {
            g_free(table_raw);
            return VIRT_DRTM_MEM_PROTECT_INVALID;
        }
        count = load_le32(table_raw + 4);
        expected_size = DRTM_TABLE_HEADER_SIZE +
                        (uint64_t)count * DRTM_REGION_DESCRIPTOR_SIZE;
        if (table_size != expected_size ||
            count > capabilities->maximum_protected_regions) {
            g_free(table_raw);
            return VIRT_DRTM_MEM_PROTECT_INVALID;
        }
    }

    decoded = g_try_malloc0(sizeof(*decoded) +
                            (size_t)count * sizeof(decoded->regions[0]));
    if (!decoded) {
        g_free(table_raw);
        return VIRT_DRTM_OUT_OF_RESOURCE;
    }

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *wire = table_raw + DRTM_TABLE_HEADER_SIZE +
                              i * DRTM_REGION_DESCRIPTOR_SIZE;
        uint64_t address = load_le64(wire);
        uint64_t size_type = load_le64(wire + 8);
        uint64_t pages = size_type & MAKE_64BIT_MASK(0, 52);
        uint64_t type = extract64(size_type, 52, 3);
        Range region;

        /*
         * Table 11 says cacheability bits[56:55] are applicable only to
         * region type 1.  R42090 requires type 0 here, so retain neither the
         * bits nor a non-normative Must-Be-Zero restriction on their value.
         */
        if (address % DRTM_PAGE_SIZE || (size_type >> 57) || type != 0 ||
            !pages || !range_make(address, pages << 12, &region) ||
            !range_is_ram(is_ram, opaque, region)) {
            goto bad_table;
        }
        decoded->regions[i].address = address;
        decoded->regions[i].size = region.end - region.start;
    }

    qsort(decoded->regions, count, sizeof(decoded->regions[0]), region_compare);
    for (uint32_t i = 1; i < count; i++) {
        Range previous = {
            .start = decoded->regions[i - 1].address,
            .end = decoded->regions[i - 1].address +
                   decoded->regions[i - 1].size,
        };
        Range region = {
            .start = decoded->regions[i].address,
            .end = decoded->regions[i].address + decoded->regions[i].size,
        };

        if (ranges_overlap(previous, region)) {
            goto bad_table;
        }
    }

    if (has_table &&
        (!regions_cover(decoded->regions, count, dlme) ||
         (has_dce && !regions_cover(decoded->regions, count, dce)))) {
        goto bad_table;
    }

    decoded->public.launch_features = features;
    decoded->public.memory_protection = memory_protection;
    decoded->public.pcr_schema = pcr_schema;
    decoded->public.tpm_hashing = features & BIT(0);
    decoded->public.image_authentication = features & BIT(6);
    decoded->public.disable_secure_interrupts = features & BIT(7);
    decoded->public.dlme_address = dlme_address;
    decoded->public.dlme_size = dlme_size;
    decoded->public.image_address = image.start;
    decoded->public.image_size = image_size;
    decoded->public.entry_address = entry.start;
    decoded->public.data_address = data.start;
    decoded->public.data_offset = data_offset;
    decoded->public.has_dce = has_dce;
    decoded->public.dce_address = dce_address;
    decoded->public.dce_size = dce_size;
    decoded->public.protection_table_address = table_address;
    decoded->public.protection_table_size = table_size;
    decoded->public.protected_region_count = count;
    decoded->public.protected_regions = decoded->regions;
    g_free(table_raw);
    *result = &decoded->public;
    return VIRT_DRTM_PARAM_SUCCESS;

bad_table:
    g_free(table_raw);
    g_free(decoded);
    return VIRT_DRTM_MEM_PROTECT_INVALID;
}
