/*
 * Arm DRTM mutable TCB hash tests
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/arm/virt-drtm-tcb.h"
#include "qemu/bswap.h"

#define SHA256_SIZE 32
#define ENTRY_SIZE  (4 + SHA256_SIZE)

static size_t make_table(uint8_t *table, size_t count, uint32_t first_id)
{
    size_t i;

    stw_le_p(table, 1);
    stw_le_p(table + 2, count);
    stw_le_p(table + 4, 0x000b);
    stw_le_p(table + 6, 0);
    for (i = 0; i < count; i++) {
        stl_le_p(table + 8 + i * ENTRY_SIZE, first_id + i);
        memset(table + 12 + i * ENTRY_SIZE, i + 1, SHA256_SIZE);
    }
    return 8 + count * ENTRY_SIZE;
}

static void test_append_duplicate_and_source(void)
{
    VirtDRTMTCBStore store;
    VirtDRTMTCBHash hashes[3];
    uint8_t table[8 + 2 * ENTRY_SIZE];
    VirtDRTMTCBResult result;
    size_t size;

    g_assert(virt_drtm_tcb_init(&store, 0x000b, 3));
    size = make_table(table, 2, 0x41424344);
    stl_le_p(table + 8, UINT32_C(0xc1424344));
    result = virt_drtm_tcb_set(&store, table, size);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_SUCCESS);
    g_assert_cmpuint(result.supplemental, ==, 2);

    size = make_table(table, 1, 0x41424344);
    result = virt_drtm_tcb_set(&store, table, size);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_SUCCESS);
    g_assert_cmpuint(result.supplemental, ==, 1);
    g_assert_cmpuint(store.count, ==, 3);
    g_assert_cmpint(virt_drtm_tcb_export(&store, hashes,
                                         ARRAY_SIZE(hashes)), ==,
                    VIRT_DRTM_TCB_NOT_LOCKED);
    g_assert_cmpint(virt_drtm_tcb_lock(&store), ==,
                    VIRT_DRTM_TCB_SUCCESS);
    g_assert_cmpint(virt_drtm_tcb_export(&store, hashes,
                                         ARRAY_SIZE(hashes)), ==,
                    VIRT_DRTM_TCB_SUCCESS);
    g_assert_cmphex(hashes[0].id, ==, 0x41424344);
    g_assert_cmphex(hashes[2].id, ==, 0x41424344);
    g_assert_cmpint(hashes[0].origin, ==,
                    VIRT_DRTM_TCB_HASH_SET_TCB_HASH);
    g_assert_cmpuint(hashes[0].digest_size, ==, SHA256_SIZE);
    g_assert_cmphex(hashes[0].digest[0], ==, 1);
}

static void test_header_validation(void)
{
    VirtDRTMTCBStore store;
    uint8_t table[8 + ENTRY_SIZE];
    VirtDRTMTCBResult result;
    size_t size;

    g_assert(!virt_drtm_tcb_init(&store, 0x0004, 1));
    g_assert(!virt_drtm_tcb_init(&store, 0x000b, 256));
    g_assert(virt_drtm_tcb_init(&store, 0x000b, 1));
    size = make_table(table, 1, 1);

#define INVALID_HEADER(offset, value) do {                                  \
        uint16_t saved = lduw_le_p(table + (offset));                       \
        stw_le_p(table + (offset), (value));                                \
        result = virt_drtm_tcb_set(&store, table, size);                    \
        g_assert_cmpint(result.status, ==,                                  \
                        VIRT_DRTM_TCB_INVALID_PARAMETERS);                  \
        g_assert_cmpuint(store.count, ==, 0);                               \
        stw_le_p(table + (offset), saved);                                  \
    } while (0)
    INVALID_HEADER(0, 2);
    INVALID_HEADER(2, 0);
    INVALID_HEADER(4, 0x000c);
    INVALID_HEADER(6, 1);
#undef INVALID_HEADER
    result = virt_drtm_tcb_set(&store, NULL, 0);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_INVALID_PARAMETERS);
    result = virt_drtm_tcb_set(&store, table, 7);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_INVALID_PARAMETERS);
    result = virt_drtm_tcb_set(&store, table, size + 1);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_INVALID_PARAMETERS);
}

static void test_atomic_capacity_and_bad_entry(void)
{
    VirtDRTMTCBStore store;
    uint8_t table[8 + 3 * ENTRY_SIZE];
    VirtDRTMTCBResult result;
    size_t size;

    g_assert(virt_drtm_tcb_init(&store, 0x000b, 2));
    g_assert_cmpint(virt_drtm_tcb_export(&store, NULL, 0), ==,
                    VIRT_DRTM_TCB_SUCCESS);
    size = make_table(table, 1, 0x10);
    result = virt_drtm_tcb_set(&store, table, size);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_SUCCESS);
    g_assert_cmpint(virt_drtm_tcb_export(&store, NULL, 0), ==,
                    VIRT_DRTM_TCB_NOT_LOCKED);

    size = make_table(table, 2, 0x20);
    result = virt_drtm_tcb_set(&store, table, size);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_OUT_OF_RESOURCE);
    g_assert_cmpuint(store.count, ==, 1);
    result = virt_drtm_tcb_set(&store, table, 8);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_OUT_OF_RESOURCE);
    g_assert_cmpuint(store.count, ==, 1);

    g_assert(virt_drtm_tcb_init(&store, 0x000b, 3));
    size = make_table(table, 3, 0x30);
    result = virt_drtm_tcb_set(&store, table, size - ENTRY_SIZE);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_INVALID_DATA);
    g_assert_cmpuint(result.supplemental, ==, 2);
    g_assert_cmpuint(store.count, ==, 0);
    result = virt_drtm_tcb_set(&store, table, size - 1);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_INVALID_DATA);
    g_assert_cmpuint(result.supplemental, ==, 2);
    g_assert_cmpuint(store.count, ==, 0);
}

static void test_lock_and_reset(void)
{
    VirtDRTMTCBStore store;
    VirtDRTMTCBHash hash;
    uint8_t table[8 + ENTRY_SIZE];
    VirtDRTMTCBResult result;
    bool ready;
    size_t size = make_table(table, 1, 1);

    g_assert(virt_drtm_tcb_init(&store, 0x000b, 2));
    g_assert_cmpint(virt_drtm_tcb_lock(&store), ==,
                    VIRT_DRTM_TCB_SUCCESS);
    g_assert_cmpint(virt_drtm_tcb_lock(&store), ==,
                    VIRT_DRTM_TCB_DENIED);
    result = virt_drtm_tcb_set(&store, table, size);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_DENIED);
    virt_drtm_tcb_reset(&store);
    g_assert_false(store.locked);
    g_assert_cmpuint(store.count, ==, 0);
    result = virt_drtm_tcb_set(&store, table, size);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_SUCCESS);
    g_assert_cmpint(virt_drtm_tcb_snapshot(&store, &hash, 1, &ready), ==,
                    VIRT_DRTM_TCB_SUCCESS);
    g_assert_false(ready);
    g_assert_cmphex(hash.id, ==, 1);
    g_assert_cmphex(hash.digest[0], ==, 1);
    virt_drtm_tcb_reset(&store);
    g_assert_cmpint(virt_drtm_tcb_export(&store, NULL, 0), ==,
                    VIRT_DRTM_TCB_SUCCESS);
}

static void test_algorithms_and_launch_data(void)
{
    static const uint16_t algorithms[] = { 0x000b, 0x000c, 0x000d };
    static const size_t digest_sizes[] = { 32, 48, 64 };
    VirtDRTMMemoryRegion map = {
        0x40000000, 0x00400000, VIRT_DRTM_MEMORY_NORMAL_CACHED, 3
    };
    const uint8_t event[] = { 1 };
    uint8_t table[8 + 64 + 4];
    VirtDRTMTCBHash hash;
    VirtDRTMDataInput data;
    VirtDRTMTCBStore store;
    VirtDRTMTCBResult result;
    uint8_t *output;
    size_t table_size, data_size, tcb_offset, i;

    for (i = 0; i < ARRAY_SIZE(algorithms); i++) {
        g_assert(virt_drtm_tcb_init(&store, algorithms[i], 1));
        stw_le_p(table, 1);
        stw_le_p(table + 2, 1);
        stw_le_p(table + 4, algorithms[i]);
        stw_le_p(table + 6, 0);
        stl_le_p(table + 8, UINT32_C(0x81234567));
        memset(table + 12, 0xa5, digest_sizes[i]);
        table_size = 12 + digest_sizes[i];
        result = virt_drtm_tcb_set(&store, table, table_size);
        g_assert_cmpint(result.status, ==, VIRT_DRTM_TCB_SUCCESS);
        g_assert_cmpint(virt_drtm_tcb_export(&store, &hash, 0), ==,
                        VIRT_DRTM_TCB_NOT_LOCKED);
        g_assert_cmpint(virt_drtm_tcb_lock(&store), ==,
                        VIRT_DRTM_TCB_SUCCESS);
        g_assert_cmpint(virt_drtm_tcb_export(&store, &hash, 0), ==,
                        VIRT_DRTM_TCB_INVALID_PARAMETERS);
        g_assert_cmpint(virt_drtm_tcb_export(&store, &hash, 1), ==,
                        VIRT_DRTM_TCB_SUCCESS);
        data = (VirtDRTMDataInput) {
            .dlme_address = 0x40000000,
            .dlme_size = 0x00400000,
            .image_address = 0x40000000,
            .image_size = 0x00200000,
            .complete_protection = true,
            .address_map = &map,
            .address_map_count = 1,
            .event_log = { event, sizeof(event) },
            .firmware_hash_algorithm = algorithms[i],
            .tcb_hashes = &hash,
            .tcb_hash_count = 1,
        };
        g_assert_cmpint(virt_drtm_data_build(&data, 0x40200000, NULL, 0,
                                             &data_size), ==,
                        VIRT_DRTM_DATA_OK);
        output = g_malloc(data_size);
        g_assert_cmpint(virt_drtm_data_build(&data, 0x40200000, output,
                                             data_size, &data_size), ==,
                        VIRT_DRTM_DATA_OK);
        tcb_offset = VIRT_DRTM_DATA_HEADER_SIZE + ldq_le_p(output + 16) +
                     ldq_le_p(output + 24) + ldq_le_p(output + 32);
        g_assert_cmphex((uint32_t)ldl_le_p(output + tcb_offset + 8), ==,
                        UINT32_C(0x81234567));
        g_assert_cmpmem(output + tcb_offset + 12, digest_sizes[i],
                        table + 12, digest_sizes[i]);
        g_free(output);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/virt-drtm-tcb/append-duplicate-source",
                    test_append_duplicate_and_source);
    g_test_add_func("/virt-drtm-tcb/header-validation",
                    test_header_validation);
    g_test_add_func("/virt-drtm-tcb/atomic-capacity-bad-entry",
                    test_atomic_capacity_and_bad_entry);
    g_test_add_func("/virt-drtm-tcb/lock-reset", test_lock_and_reset);
    g_test_add_func("/virt-drtm-tcb/algorithms-launch-data",
                    test_algorithms_and_launch_data);
    return g_test_run();
}
