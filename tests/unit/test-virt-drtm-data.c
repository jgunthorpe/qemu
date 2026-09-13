/*
 * Arm DRTM DLME data serializer tests
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "hw/arm/virt-drtm-data.h"
#include "qemu/bswap.h"

#define DLME_ADDRESS 0x40000000
#define DLME_SIZE    0x00400000
#define DATA_ADDRESS 0x40200000

static const uint8_t event[] = { 0xa1, 0xb2, 0xc3 };
static const uint32_t required_ids[] = {
    0x43495041, 0x4746434d, 0x54445447, 0x54524f49, 0x324d5054,
};

typedef struct Fixture {
    VirtDRTMMemoryRegion map[5];
    VirtDRTMTCBHash hashes[5];
    uint8_t digests[5][64];
    VirtDRTMDataInput input;
} Fixture;

static void fixture_init(Fixture *f, uint16_t algorithm, size_t digest_size)
{
    size_t i;

    memset(f, 0, sizeof(*f));
    /* Unsorted authoritative virt-like ranges with real address holes. */
    f->map[0] = (VirtDRTMMemoryRegion) {
        DLME_ADDRESS, 0x08000000, VIRT_DRTM_MEMORY_NORMAL_CACHED, 3
    };
    f->map[1] = (VirtDRTMMemoryRegion) {
        0x30000000, 0x1000, VIRT_DRTM_MEMORY_NON_VOLATILE, 0
    };
    f->map[2] = (VirtDRTMMemoryRegion) {
        0x10000000, 0x10000000, VIRT_DRTM_MEMORY_MMIO, 0
    };
    f->map[3] = (VirtDRTMMemoryRegion) {
        0x08000000, 0x08000000, VIRT_DRTM_MEMORY_MMIO, 0
    };
    f->map[4] = (VirtDRTMMemoryRegion) {
        0x800000000, 0x10000000, VIRT_DRTM_MEMORY_MMIO, 0
    };
    for (i = 0; i < ARRAY_SIZE(f->hashes); i++) {
        memset(f->digests[i], i + 1, digest_size);
        f->hashes[i] = (VirtDRTMTCBHash) {
            .id = required_ids[i],
            .digest = f->digests[i],
            .digest_size = digest_size,
            .origin = i == 1 ? VIRT_DRTM_TCB_HASH_SET_TCB_HASH :
                               VIRT_DRTM_TCB_HASH_IMPLEMENTATION,
        };
    }
    f->input = (VirtDRTMDataInput) {
        .dlme_address = DLME_ADDRESS,
        .dlme_size = DLME_SIZE,
        .image_address = DLME_ADDRESS,
        .image_size = 0x200000,
        .complete_protection = true,
        .address_map = f->map,
        .address_map_count = ARRAY_SIZE(f->map),
        .event_log = { event, sizeof(event) },
        .firmware_hash_algorithm = algorithm,
        .tcb_hashes = f->hashes,
        .tcb_hash_count = ARRAY_SIZE(f->hashes),
    };
}

static VirtDRTMDataStatus build(Fixture *f, uint8_t *out, size_t capacity,
                                size_t *required)
{
    return virt_drtm_data_build(&f->input, DATA_ADDRESS, out, capacity,
                                required);
}

static void test_layout(void)
{
    Fixture f;
    uint8_t *out;
    size_t size, protected_off = 64, map_off = 88;
    size_t event_off = map_off + 72, tcb_off = event_off + sizeof(event);

    fixture_init(&f, 0x000b, 32);
    g_assert_cmpint(build(&f, NULL, 0, &size), ==, VIRT_DRTM_DATA_OK);
    g_assert_cmpuint(size, ==, 64 + 24 + 72 + sizeof(event) + 188);
    out = g_malloc0(size);
    g_assert_cmpint(build(&f, out, size, &size), ==, VIRT_DRTM_DATA_OK);
    g_assert_cmpuint(lduw_le_p(out), ==, 1);
    g_assert_cmpuint(lduw_le_p(out + 2), ==, 64);
    g_assert_cmpuint(ldl_le_p(out + 4), ==, 0);
    g_assert_cmpuint(ldq_le_p(out + 8), ==, size);
    g_assert_cmpuint(ldq_le_p(out + 16), ==, 24);
    g_assert_cmpuint(ldq_le_p(out + 24), ==, 72);
    g_assert_cmpuint(ldq_le_p(out + 32), ==, sizeof(event));
    g_assert_cmpuint(ldq_le_p(out + 40), ==, 188);
    g_assert_cmpuint(ldq_le_p(out + 48), ==, 0);
    g_assert_cmpuint(ldq_le_p(out + 56), ==, 0);
    g_assert_cmpuint(ldl_le_p(out + protected_off + 4), ==, 1);
    g_assert_cmphex(ldq_le_p(out + protected_off + 8), ==, 0);
    g_assert_cmphex(ldq_le_p(out + protected_off + 16), ==,
                    (1ULL << 52) - 1);
    g_assert_cmpuint(ldl_le_p(out + map_off + 4), ==, 4);
    g_assert_cmphex(ldq_le_p(out + map_off + 8), ==, 0x08000000);
    g_assert_cmphex(ldq_le_p(out + map_off + 16), ==,
                    0x18000 | (2ULL << 52));
    g_assert_cmphex(ldq_le_p(out + map_off + 24), ==, 0x30000000);
    g_assert_cmphex(ldq_le_p(out + map_off + 40), ==, DLME_ADDRESS);
    g_assert_cmpmem(out + event_off, sizeof(event), event, sizeof(event));
    g_assert_cmpuint(lduw_le_p(out + tcb_off), ==, 1);
    g_assert_cmpuint(lduw_le_p(out + tcb_off + 2), ==, 5);
    g_assert_cmpuint(lduw_le_p(out + tcb_off + 4), ==, 0xb);
    g_assert_cmphex(ldl_le_p(out + tcb_off + 8), ==, required_ids[0]);
    g_assert_cmpuint((uint32_t)ldl_le_p(out + tcb_off + 44), ==,
                     required_ids[1] | UINT32_C(0x80000000));
    g_assert_cmpmem(out + tcb_off + 48, 32, f.digests[1], 32);
    g_free(out);
}

static void test_bounds_two_pass(void)
{
    Fixture f;
    uint8_t *out;
    size_t size, second_size;

    fixture_init(&f, 0xb, 32);
    g_assert_cmpint(build(&f, NULL, 0, &size), ==, VIRT_DRTM_DATA_OK);
    out = g_malloc(size);
    memset(out, 0x5a, size);
    second_size = 0;
    g_assert_cmpint(build(&f, out, size - 1, &second_size), ==,
                    VIRT_DRTM_DATA_TOO_SMALL);
    g_assert_cmpuint(second_size, ==, size);
    g_assert_cmphex(out[0], ==, 0x5a);
    g_assert_cmpint(build(&f, out, size, &second_size), ==,
                    VIRT_DRTM_DATA_OK);
    g_assert_cmpuint(second_size, ==, size);
    g_free(out);
    f.input.event_log.size = SIZE_MAX;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_OVERFLOW);
    fixture_init(&f, 0xb, 32);
    f.input.address_map_count = (size_t)UINT32_MAX + 1;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_OVERFLOW);
}

static void test_map_contract(void)
{
    Fixture f;
    size_t size;

    fixture_init(&f, 0xb, 32);
    f.map[0].size = 0x00100000;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_INVALID);
    fixture_init(&f, 0xb, 32);
    f.map[0].type = VIRT_DRTM_MEMORY_MMIO;
    f.map[0].cacheability = 0;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_INVALID);
    fixture_init(&f, 0xb, 32);
    f.map[4].address = DLME_ADDRESS;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_INVALID);
    fixture_init(&f, 0xb, 32);
    f.map[1].cacheability = 1;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_INVALID);
}

static void test_geometry(void)
{
    Fixture f;
    size_t size;

    fixture_init(&f, 0xb, 32);
    f.input.dlme_address++;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_INVALID);
    fixture_init(&f, 0xb, 32);
    f.input.image_address++;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_INVALID);
    fixture_init(&f, 0xb, 32);
    f.input.image_size = DATA_ADDRESS - DLME_ADDRESS + 1;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_INVALID);
    fixture_init(&f, 0xb, 32);
    f.input.dlme_size++;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_OK);
}

static void test_tcb_algorithms(void)
{
    const uint16_t algorithms[] = { 0xb, 0xc, 0xd };
    const size_t digest_sizes[] = { 32, 48, 64 };
    Fixture f;
    uint8_t *out;
    size_t size, i;

    for (i = 0; i < ARRAY_SIZE(algorithms); i++) {
        size_t tcb_size = 8 + 5 * (4 + digest_sizes[i]);
        fixture_init(&f, algorithms[i], digest_sizes[i]);
        g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                        VIRT_DRTM_DATA_OK);
        out = g_malloc(size);
        g_assert_cmpint(build(&f, out, size, &size), ==,
                        VIRT_DRTM_DATA_OK);
        g_assert_cmpuint(ldq_le_p(out + 40), ==, tcb_size);
        g_assert_cmpuint(lduw_le_p(out + size - tcb_size + 4), ==,
                         algorithms[i]);
        g_free(out);
    }
}

static void test_tcb_validation(void)
{
    Fixture f;
    size_t size;

    fixture_init(&f, 0xb, 32);
    f.hashes[0].digest_size = 31;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_INVALID);
    fixture_init(&f, 0xb, 32);
    f.hashes[0].id |= 0x80000000;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_INVALID);
    fixture_init(&f, 0xb, 32);
    f.hashes[0].origin = 9;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_INVALID);
    fixture_init(&f, 0x4, 20);
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_INVALID);
    fixture_init(&f, 0xb, 32);
    f.hashes[0].id = 0x11111111;
    for (size_t i = 1; i < ARRAY_SIZE(f.hashes); i++) {
        f.hashes[i].id = 0x11111111;
    }
    g_assert_cmpint(build(&f, NULL, 0, &size), ==, VIRT_DRTM_DATA_OK);
    fixture_init(&f, 0xb, 32);
    f.input.tcb_hash_count = (size_t)UINT16_MAX + 1;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==,
                    VIRT_DRTM_DATA_OVERFLOW);
}

static void test_empty_tcb_region(void)
{
    Fixture f;
    uint8_t *out;
    size_t size;

    fixture_init(&f, 0xb, 32);
    f.input.tcb_hashes = NULL;
    f.input.tcb_hash_count = 0;
    f.input.firmware_hash_algorithm = 0;
    g_assert_cmpint(build(&f, NULL, 0, &size), ==, VIRT_DRTM_DATA_OK);
    out = g_malloc0(size);
    g_assert_cmpint(build(&f, out, size, &size), ==, VIRT_DRTM_DATA_OK);
    g_assert_cmpuint(ldq_le_p(out + 40), ==, 0);
    g_assert_cmpuint(ldq_le_p(out + 48), ==, 0);
    g_assert_cmpuint(size, ==,
                     VIRT_DRTM_DATA_HEADER_SIZE + ldq_le_p(out + 16) +
                     ldq_le_p(out + 24) + ldq_le_p(out + 32));
    g_free(out);
}

static void test_protected_regions(void)
{
    Fixture f;
    VirtDRTMMemoryRegion regions[3] = {
        { 0x40400000, 0x1000, VIRT_DRTM_MEMORY_NORMAL, 0 },
        { 0x40000000, 0x1000, VIRT_DRTM_MEMORY_NORMAL, 0 },
        { 0x40001000, 0x1000, VIRT_DRTM_MEMORY_NORMAL, 0 },
    };
    uint8_t *out;
    size_t size;

    fixture_init(&f, 0xb, 32);
    f.input.complete_protection = false;
    f.input.protected_regions = regions;
    f.input.protected_region_count = ARRAY_SIZE(regions);
    g_assert_cmpint(build(&f, NULL, 0, &size), ==, VIRT_DRTM_DATA_OK);
    out = g_malloc(size);
    g_assert_cmpint(build(&f, out, size, &size), ==, VIRT_DRTM_DATA_OK);
    g_assert_cmpuint(ldl_le_p(out + 68), ==, 2);
    g_assert_cmphex(ldq_le_p(out + 72), ==, 0x40000000);
    g_assert_cmphex(ldq_le_p(out + 80), ==, 2);
    g_free(out);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/virt-drtm-data/layout", test_layout);
    g_test_add_func("/virt-drtm-data/bounds-two-pass", test_bounds_two_pass);
    g_test_add_func("/virt-drtm-data/map-contract", test_map_contract);
    g_test_add_func("/virt-drtm-data/geometry", test_geometry);
    g_test_add_func("/virt-drtm-data/tcb-algorithms", test_tcb_algorithms);
    g_test_add_func("/virt-drtm-data/tcb-validation", test_tcb_validation);
    g_test_add_func("/virt-drtm-data/empty-tcb-region",
                    test_empty_tcb_region);
    g_test_add_func("/virt-drtm-data/protected", test_protected_regions);
    return g_test_run();
}
