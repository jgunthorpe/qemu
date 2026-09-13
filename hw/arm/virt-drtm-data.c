/*
 * Arm DRTM DLME data serializer
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/arm/virt-drtm-data.h"
#include "qemu/bswap.h"

#define REGION_TABLE_HEADER_SIZE 8
#define REGION_DESCRIPTOR_SIZE   16
#define REGION_PAGES_MASK        ((1ULL << 52) - 1)
#define TCB_HEADER_SIZE           8

typedef struct RegionList {
    VirtDRTMMemoryRegion *regions;
    size_t count;
    size_t wire_size;
} RegionList;

static bool add_size(size_t *total, size_t add)
{
    if (add > SIZE_MAX - *total) {
        return false;
    }
    *total += add;
    return true;
}

static bool range_valid(uint64_t address, uint64_t size)
{
    return size && size - 1 <= UINT64_MAX - address;
}

static bool range_contains(uint64_t outer_address, uint64_t outer_size,
                           uint64_t inner_address, uint64_t inner_size)
{
    return range_valid(outer_address, outer_size) &&
           range_valid(inner_address, inner_size) &&
           inner_address >= outer_address &&
           inner_address + inner_size - 1 <= outer_address + outer_size - 1;
}

static int region_compare(const void *ap, const void *bp)
{
    const VirtDRTMMemoryRegion *a = ap;
    const VirtDRTMMemoryRegion *b = bp;

    return a->address < b->address ? -1 : a->address > b->address;
}

static bool same_semantics(const VirtDRTMMemoryRegion *a,
                           const VirtDRTMMemoryRegion *b)
{
    return a->type == b->type && a->cacheability == b->cacheability;
}

static VirtDRTMDataStatus prepare_regions(const VirtDRTMMemoryRegion *input,
                                          size_t count, bool protected,
                                          RegionList *result)
{
    size_t i;

    if (!count || !input || count > UINT32_MAX ||
        count > (SIZE_MAX - REGION_TABLE_HEADER_SIZE) /
                REGION_DESCRIPTOR_SIZE) {
        return count > UINT32_MAX ? VIRT_DRTM_DATA_OVERFLOW :
                                   VIRT_DRTM_DATA_INVALID;
    }
    result->regions = g_memdup2(input, count * sizeof(*input));
    qsort(result->regions, count, sizeof(*input), region_compare);

    result->count = 0;
    for (i = 0; i < count; i++) {
        VirtDRTMMemoryRegion *r = &result->regions[i];
        VirtDRTMMemoryRegion *last;

        if (!r->size || (r->address | r->size) & (VIRT_DRTM_PAGE_SIZE - 1) ||
            r->size / VIRT_DRTM_PAGE_SIZE > REGION_PAGES_MASK ||
            r->address > UINT64_MAX - r->size) {
            goto invalid;
        }
        if (protected) {
            if (r->type != VIRT_DRTM_MEMORY_NORMAL || r->cacheability) {
                goto invalid;
            }
        } else if (r->type < VIRT_DRTM_MEMORY_NORMAL_CACHED ||
                   r->type > VIRT_DRTM_MEMORY_UNUSABLE ||
                   (r->type != VIRT_DRTM_MEMORY_NORMAL_CACHED &&
                    r->cacheability) || r->cacheability > 3) {
            goto invalid;
        }

        if (!result->count) {
            result->regions[result->count++] = *r;
            continue;
        }
        last = &result->regions[result->count - 1];
        if (r->address < last->address + last->size) {
            goto invalid;
        }
        if (r->address == last->address + last->size &&
            same_semantics(last, r)) {
            if (r->size > UINT64_MAX - last->size ||
                (last->size + r->size) / VIRT_DRTM_PAGE_SIZE >
                REGION_PAGES_MASK) {
                g_free(result->regions);
                return VIRT_DRTM_DATA_OVERFLOW;
            }
            last->size += r->size;
        } else {
            result->regions[result->count++] = *r;
        }
    }
    result->wire_size = REGION_TABLE_HEADER_SIZE +
                        result->count * REGION_DESCRIPTOR_SIZE;
    return VIRT_DRTM_DATA_OK;

invalid:
    g_free(result->regions);
    return VIRT_DRTM_DATA_INVALID;
}

static void write_region_table(uint8_t *p, const RegionList *list)
{
    size_t i;

    stw_le_p(p, 1);
    stw_le_p(p + 2, 0);
    stl_le_p(p + 4, list->count);
    for (i = 0; i < list->count; i++) {
        const VirtDRTMMemoryRegion *r = &list->regions[i];
        uint64_t size_type = r->size / VIRT_DRTM_PAGE_SIZE;

        size_type |= (uint64_t)r->type << 52;
        size_type |= (uint64_t)r->cacheability << 55;
        stq_le_p(p + 8 + i * 16, r->address);
        stq_le_p(p + 16 + i * 16, size_type);
    }
}

static size_t tcb_digest_size(uint16_t algorithm)
{
    switch (algorithm) {
    case 0x000b: return 32;
    case 0x000c: return 48;
    case 0x000d: return 64;
    default: return 0;
    }
}

static VirtDRTMDataStatus validate_tcb(const VirtDRTMDataInput *input,
                                       size_t *wire_size)
{
    size_t digest = tcb_digest_size(input->firmware_hash_algorithm);
    size_t entry_size, i;

    if (!input->tcb_hash_count) {
        *wire_size = 0;
        return VIRT_DRTM_DATA_OK;
    }
    if (!digest || !input->tcb_hashes) {
        return VIRT_DRTM_DATA_INVALID;
    }
    if (input->tcb_hash_count > UINT16_MAX ||
        input->tcb_hash_count > (SIZE_MAX - TCB_HEADER_SIZE) / (digest + 4)) {
        return VIRT_DRTM_DATA_OVERFLOW;
    }
    entry_size = digest + 4;
    *wire_size = TCB_HEADER_SIZE + input->tcb_hash_count * entry_size;
    for (i = 0; i < input->tcb_hash_count; i++) {
        const VirtDRTMTCBHash *hash = &input->tcb_hashes[i];

        if (hash->id & 0x80000000 || !hash->digest ||
            hash->digest_size != digest ||
            (hash->origin != VIRT_DRTM_TCB_HASH_IMPLEMENTATION &&
             hash->origin != VIRT_DRTM_TCB_HASH_SET_TCB_HASH)) {
            return VIRT_DRTM_DATA_INVALID;
        }
    }
    return VIRT_DRTM_DATA_OK;
}

static void write_tcb(uint8_t *p, const VirtDRTMDataInput *input)
{
    size_t digest = tcb_digest_size(input->firmware_hash_algorithm);
    size_t i;

    stw_le_p(p, 1);
    stw_le_p(p + 2, input->tcb_hash_count);
    stw_le_p(p + 4, input->firmware_hash_algorithm);
    stw_le_p(p + 6, 0);
    for (i = 0; i < input->tcb_hash_count; i++) {
        const VirtDRTMTCBHash *hash = &input->tcb_hashes[i];
        uint32_t id = hash->id;

        if (hash->origin == VIRT_DRTM_TCB_HASH_SET_TCB_HASH) {
            id |= 0x80000000;
        }
        stl_le_p(p + TCB_HEADER_SIZE + i * (digest + 4), id);
        memcpy(p + TCB_HEADER_SIZE + i * (digest + 4) + 4,
               hash->digest, digest);
    }
}

static bool map_covers_normal(const RegionList *map, uint64_t address,
                              uint64_t size)
{
    uint64_t end = address + size - 1;
    size_t i;

    for (i = 0; i < map->count; i++) {
        const VirtDRTMMemoryRegion *r = &map->regions[i];
        uint64_t region_end = r->address + r->size - 1;

        if (r->address > address) {
            return false;
        }
        if (region_end < address) {
            continue;
        }
        if (r->type != VIRT_DRTM_MEMORY_NORMAL_CACHED) {
            return false;
        }
        if (region_end >= end) {
            return true;
        }
        address = region_end + 1;
    }
    return false;
}

VirtDRTMDataStatus virt_drtm_data_build(const VirtDRTMDataInput *input,
                                        uint64_t output_address,
                                        uint8_t *output, size_t output_size,
                                        size_t *required_size)
{
    VirtDRTMMemoryRegion sentinel = {
        0, REGION_PAGES_MASK * 4096, VIRT_DRTM_MEMORY_NORMAL, 0
    };
    RegionList protected = { 0 }, map = { 0 };
    VirtDRTMDataStatus status;
    size_t total = VIRT_DRTM_DATA_HEADER_SIZE, tcb_size = 0, offset;

    if (!input || !required_size || output_address % VIRT_DRTM_PAGE_SIZE ||
        !input->event_log.data || !input->event_log.size) {
        return VIRT_DRTM_DATA_INVALID;
    }
    if ((input->dlme_address | input->image_address) &
        (VIRT_DRTM_PAGE_SIZE - 1) ||
        !range_contains(input->dlme_address, input->dlme_size,
                        input->image_address, input->image_size) ||
        !range_contains(input->dlme_address, input->dlme_size,
                        output_address, 1) ||
        input->image_address + input->image_size - 1 >= output_address) {
        return VIRT_DRTM_DATA_INVALID;
    }
    status = validate_tcb(input, &tcb_size);
    if (status != VIRT_DRTM_DATA_OK) {
        return status;
    }
    if (input->complete_protection) {
        if (input->protected_region_count || input->protected_regions) {
            return VIRT_DRTM_DATA_INVALID;
        }
        status = prepare_regions(&sentinel, 1, true, &protected);
    } else {
        status = prepare_regions(input->protected_regions,
                                 input->protected_region_count, true,
                                 &protected);
    }
    if (status != VIRT_DRTM_DATA_OK) {
        return status;
    }
    status = prepare_regions(input->address_map, input->address_map_count,
                             false, &map);
    if (status != VIRT_DRTM_DATA_OK) {
        g_free(protected.regions);
        return status;
    }
    if (!map_covers_normal(&map, input->dlme_address, input->dlme_size)) {
        status = VIRT_DRTM_DATA_INVALID;
        goto out;
    }

    if (!add_size(&total, protected.wire_size) ||
        !add_size(&total, map.wire_size) ||
        !add_size(&total, input->event_log.size) ||
        !add_size(&total, tcb_size) ||
        total - 1 > UINT64_MAX - output_address) {
        status = VIRT_DRTM_DATA_OVERFLOW;
        goto out;
    }
    if (!range_contains(input->dlme_address, input->dlme_size,
                        output_address, total)) {
        status = VIRT_DRTM_DATA_TOO_SMALL;
        goto out;
    }
    *required_size = total;
    if (!output) {
        status = VIRT_DRTM_DATA_OK;
        goto out;
    }
    if (output_size < total) {
        status = VIRT_DRTM_DATA_TOO_SMALL;
        goto out;
    }

    memset(output, 0, total);
    stw_le_p(output, 1);
    stw_le_p(output + 2, VIRT_DRTM_DATA_HEADER_SIZE);
    stq_le_p(output + 8, total);
    stq_le_p(output + 16, protected.wire_size);
    stq_le_p(output + 24, map.wire_size);
    stq_le_p(output + 32, input->event_log.size);
    stq_le_p(output + 40, tcb_size);
    stq_le_p(output + 48, 0);

    offset = VIRT_DRTM_DATA_HEADER_SIZE;
    write_region_table(output + offset, &protected);
    offset += protected.wire_size;
    write_region_table(output + offset, &map);
    offset += map.wire_size;
    memcpy(output + offset, input->event_log.data, input->event_log.size);
    offset += input->event_log.size;
    if (tcb_size) {
        write_tcb(output + offset, input);
        offset += tcb_size;
    }
    assert(offset == total);
    status = VIRT_DRTM_DATA_OK;

out:
    g_free(map.regions);
    g_free(protected.regions);
    return status;
}
