/*
 * Arm DRTM launch parameter decoder tests
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "hw/arm/virt-drtm-params.h"

#define PARAM_ADDR 0x1000
#define TABLE_ADDR 0x8000
#define DLME_ADDR  0x10000
#define DCE_ADDR   0x20000

typedef struct Fixture {
    uint8_t params[VIRT_DRTM_PARAMETERS_SIZE];
    uint8_t table[64];
    size_t params_readable;
    size_t table_readable;
    uint64_t nonram_start;
    uint64_t nonram_size;
    unsigned int params_reads;
    unsigned int table_reads;
    bool poison_table_after_read;
} Fixture;

static const VirtDRTMCapabilities all_caps = {
    .memory_protection_mask = BIT(0) | BIT(1),
    .pcr_schema_mask = BIT(0) | BIT(1),
    .maximum_protected_regions = 4,
    .tpm_hashing = true,
    .image_authentication = true,
    .disable_secure_interrupts = true,
};

static void st16(uint8_t *p, uint16_t value)
{
    p[0] = value;
    p[1] = value >> 8;
}

static void st32(uint8_t *p, uint32_t value)
{
    st16(p, value);
    st16(p + 2, value >> 16);
}

static void st64(uint8_t *p, uint64_t value)
{
    st32(p, value);
    st32(p + 4, value >> 32);
}

static bool test_read(void *opaque, uint64_t address, void *buffer, size_t size)
{
    Fixture *f = opaque;
    const uint8_t *source;
    size_t available;

    if (address == PARAM_ADDR) {
        source = f->params;
        available = f->params_readable;
        f->params_reads++;
    } else if (address == TABLE_ADDR) {
        source = f->table;
        available = f->table_readable;
        f->table_reads++;
    } else {
        return false;
    }
    if (size > available) {
        return false;
    }
    memcpy(buffer, source, size);
    if (address == TABLE_ADDR && f->poison_table_after_read) {
        memset(f->table, 0xa5, sizeof(f->table));
    }
    return true;
}

static bool test_is_ram(void *opaque, uint64_t address, uint64_t size)
{
    Fixture *f = opaque;
    uint64_t end = address + size;
    uint64_t nonram_end = f->nonram_start + f->nonram_size;

    return !f->nonram_size || end <= f->nonram_start ||
           nonram_end <= address;
}

static void fixture_init(Fixture *f)
{
    memset(f, 0, sizeof(*f));
    f->params_readable = sizeof(f->params);
    f->table_readable = sizeof(f->table);
    st16(f->params, 2);
    st64(f->params + 8, DLME_ADDR);
    st64(f->params + 16, 0x4000);
    st64(f->params + 24, 0);
    st64(f->params + 32, 0xfff);
    st64(f->params + 40, 0x1000);
    st64(f->params + 48, 0x1000);
}

static VirtDRTMParamStatus decode(Fixture *f,
                                  const VirtDRTMCapabilities *caps,
                                  const VirtDRTMParameters **result)
{
    return virt_drtm_params_decode(PARAM_ADDR, caps, test_read,
                                   test_is_ram, f, result);
}

static void expect_status(Fixture *f, VirtDRTMParamStatus expected)
{
    const VirtDRTMParameters *result = (void *)1;

    g_assert_cmpint(decode(f, &all_caps, &result), ==, expected);
    if (expected == VIRT_DRTM_PARAM_SUCCESS) {
        g_assert_nonnull(result);
        virt_drtm_params_free(result);
    } else {
        g_assert_null(result);
    }
}

static void expect_status_caps(Fixture *f, const VirtDRTMCapabilities *caps,
                               VirtDRTMParamStatus expected)
{
    const VirtDRTMParameters *result = NULL;

    g_assert_cmpint(decode(f, caps, &result), ==, expected);
    if (result) {
        virt_drtm_params_free(result);
    }
}

static void enable_table(Fixture *f, uint32_t count)
{
    st32(f->params + 4, BIT(3));
    st64(f->params + 72, TABLE_ADDR);
    st64(f->params + 80, 8 + 16 * count);
    st16(f->table, 1);
    st32(f->table + 4, count);
}

static void set_region(Fixture *f, unsigned int n, uint64_t address,
                       uint64_t pages, unsigned int type)
{
    st64(f->table + 8 + n * 16, address);
    st64(f->table + 16 + n * 16, pages | (uint64_t)type << 52);
}

static void enable_dce(Fixture *f, VirtDRTMCapabilities *caps,
                       uint64_t address, uint64_t size)
{
    caps->minimum_dce_pages = 1;
    st64(f->params + 56, address);
    st64(f->params + 64, size);
}

static void test_valid_complete(void)
{
    Fixture f;
    const VirtDRTMParameters *p;
    VirtDRTMCapabilities complete_only = all_caps;

    fixture_init(&f);
    complete_only.memory_protection_mask = BIT(0);
    complete_only.maximum_protected_regions = 0;
    g_assert_cmpint(decode(&f, &complete_only, &p), ==, 0);
    g_assert_cmphex(p->image_address, ==, DLME_ADDR);
    g_assert_cmphex(p->entry_address, ==, DLME_ADDR + 0xfff);
    g_assert_cmphex(p->data_address, ==, DLME_ADDR + 0x1000);
    g_assert_false(p->has_dce);
    g_assert_cmpuint(p->protected_region_count, ==, 0);
    virt_drtm_params_free(p);

    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    expect_status_caps(&f, &complete_only, VIRT_DRTM_INVALID_PARAMETERS);
}

static void test_parameter_fetch(void)
{
    Fixture f;
    const VirtDRTMParameters *result;

    fixture_init(&f);
    f.params_readable--;
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    g_assert_cmpint(virt_drtm_params_decode(PARAM_ADDR + 1, &all_caps,
                                            test_read, test_is_ram, &f,
                                            &result), ==,
                    VIRT_DRTM_INVALID_PARAMETERS);
    f.nonram_start = PARAM_ADDR;
    f.nonram_size = sizeof(f.params);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
}

static void test_revision_reserved(void)
{
    Fixture f;

    fixture_init(&f);
    st16(f.params, 1);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st16(f.params + 2, 1);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
}

static void test_reserved_bit_mutations(void)
{
    Fixture f;

    for (unsigned int bit = 0; bit < 16; bit++) {
        fixture_init(&f);
        st16(f.params + 2, BIT(bit));
        expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    }
    for (unsigned int bit = 8; bit < 32; bit++) {
        fixture_init(&f);
        st32(f.params + 4, BIT(bit));
        expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    }
}

static void test_features(void)
{
    Fixture f;
    VirtDRTMCapabilities caps = all_caps;

    fixture_init(&f);
    st32(f.params + 4, BIT(8));
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st32(f.params + 4, 2 << 3);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st32(f.params + 4, 2 << 1);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st32(f.params + 4, 1 << 1);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st32(f.params + 4, BIT(6) | (1 << 1));
    caps.image_authentication = false;
    g_assert_cmpint(decode(&f, &caps, &(const VirtDRTMParameters *){ 0 }), ==,
                    VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st32(f.params + 4, BIT(0));
    caps = all_caps;
    caps.tpm_hashing = false;
    g_assert_cmpint(decode(&f, &caps, &(const VirtDRTMParameters *){ 0 }), ==,
                    VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    caps = all_caps;
    caps.memory_protection_mask = BIT(1);
    g_assert_cmpint(decode(&f, &caps, &(const VirtDRTMParameters *){ 0 }), ==,
                    VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    caps = all_caps;
    caps.pcr_schema_mask = BIT(1);
    g_assert_cmpint(decode(&f, &caps, &(const VirtDRTMParameters *){ 0 }), ==,
                    VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st32(f.params + 4, BIT(7));
    caps = all_caps;
    caps.disable_secure_interrupts = false;
    g_assert_cmpint(decode(&f, &caps, &(const VirtDRTMParameters *){ 0 }), ==,
                    VIRT_DRTM_INVALID_PARAMETERS);
}

static void test_capability_sizes(void)
{
    Fixture f;
    VirtDRTMCapabilities caps = all_caps;
    const VirtDRTMParameters *result = NULL;

    fixture_init(&f);
    caps.minimum_dlme_data_pages = 4;
    g_assert_cmpint(decode(&f, &caps, &result), ==,
                    VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    caps = all_caps;
    caps.minimum_dce_pages = 2;
    g_assert_cmpint(decode(&f, &caps, &result), ==,
                    VIRT_DRTM_INVALID_PARAMETERS);
    st64(f.params + 56, DCE_ADDR);
    st64(f.params + 64, 0x1000);
    g_assert_cmpint(decode(&f, &caps, &result), ==,
                    VIRT_DRTM_INVALID_PARAMETERS);
    st64(f.params + 64, 0x2000);
    g_assert_cmpint(decode(&f, &caps, &result), ==,
                    VIRT_DRTM_PARAM_SUCCESS);
    virt_drtm_params_free(result);
}

static void test_dlme_boundaries(void)
{
    Fixture f;

    fixture_init(&f);
    st64(f.params + 16, 0);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st64(f.params + 40, 0);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st64(f.params + 32, 0x1000);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st64(f.params + 40, 0x1001);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st64(f.params + 48, 0x4000);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st64(f.params + 8, UINT64_MAX & ~0xfffULL);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);

    fixture_init(&f);
    st64(f.params + 24, UINT64_MAX);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);

    fixture_init(&f);
    st64(f.params + 40, UINT64_MAX);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);

    /* A contained image cannot wrap if its containing DLME range does not. */
    fixture_init(&f);
    st64(f.params + 8, UINT64_MAX - 0x2fff);
    st64(f.params + 16, 0x2000);
    st64(f.params + 24, 0);
    st64(f.params + 32, 0xfff);
    st64(f.params + 40, 0x1000);
    st64(f.params + 48, 0x1000);
    expect_status(&f, VIRT_DRTM_PARAM_SUCCESS);

    fixture_init(&f);
    st64(f.params + 8, UINT64_MAX - 0xfff);
    st64(f.params + 16, 0x2000);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
}

static void test_dlme_alignment_and_ram(void)
{
    Fixture f;

    fixture_init(&f);
    st64(f.params + 24, 1);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st64(f.params + 48, 0x1001);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    f.nonram_start = DLME_ADDR + 0x3000;
    f.nonram_size = 0x1000;
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
}

static void test_dce_pair_and_overlap(void)
{
    Fixture f;
    VirtDRTMCapabilities caps = all_caps;

    fixture_init(&f);
    st64(f.params + 56, DCE_ADDR);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st64(f.params + 64, 0x1000);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st64(f.params + 56, DCE_ADDR);
    st64(f.params + 64, 0x1000);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st64(f.params + 56, DLME_ADDR + 0x1000);
    st64(f.params + 64, 0x1000);
    caps.minimum_dce_pages = 1;
    expect_status_caps(&f, &caps, VIRT_DRTM_INVALID_PARAMETERS);
    fixture_init(&f);
    st64(f.params + 56, DCE_ADDR);
    st64(f.params + 64, 0x1000);
    expect_status_caps(&f, &caps, VIRT_DRTM_PARAM_SUCCESS);
}

static void test_dce_range_validation(void)
{
    Fixture f;
    VirtDRTMCapabilities caps = all_caps;

    fixture_init(&f);
    enable_dce(&f, &caps, DCE_ADDR + 1, 0x1000);
    expect_status_caps(&f, &caps, VIRT_DRTM_INVALID_PARAMETERS);

    fixture_init(&f);
    enable_dce(&f, &caps, DCE_ADDR, 0);
    expect_status_caps(&f, &caps, VIRT_DRTM_INVALID_PARAMETERS);

    fixture_init(&f);
    caps.minimum_dce_pages = 2;
    st64(f.params + 56, DCE_ADDR);
    st64(f.params + 64, 0x1000);
    expect_status_caps(&f, &caps, VIRT_DRTM_INVALID_PARAMETERS);

    fixture_init(&f);
    caps = all_caps;
    enable_dce(&f, &caps, UINT64_MAX & ~0xfffULL, 0x2000);
    expect_status_caps(&f, &caps, VIRT_DRTM_INVALID_PARAMETERS);

    fixture_init(&f);
    caps = all_caps;
    enable_dce(&f, &caps, DCE_ADDR, 0x1000);
    f.nonram_start = DCE_ADDR;
    f.nonram_size = 0x1000;
    expect_status_caps(&f, &caps, VIRT_DRTM_INVALID_PARAMETERS);
}

static void test_adjacent_parameter_ranges(void)
{
    Fixture f;
    VirtDRTMCapabilities caps = all_caps;

    fixture_init(&f);
    enable_dce(&f, &caps, DLME_ADDR + 0x4000, 0x1000);
    expect_status_caps(&f, &caps, VIRT_DRTM_PARAM_SUCCESS);

    fixture_init(&f);
    st64(f.params + 8, 0x4000);
    enable_table(&f, 1);
    set_region(&f, 0, 0x4000, 4, 0);
    expect_status(&f, VIRT_DRTM_PARAM_SUCCESS);
}

static void test_valid_table_and_coverage(void)
{
    Fixture f;
    const VirtDRTMParameters *p;
    VirtDRTMCapabilities caps = all_caps;

    fixture_init(&f);
    enable_table(&f, 2);
    set_region(&f, 0, DLME_ADDR, 2, 0);
    set_region(&f, 1, DLME_ADDR + 0x2000, 2, 0);
    caps.maximum_protected_regions = 2;
    g_assert_cmpint(decode(&f, &caps, &p), ==, 0);
    g_assert_cmpuint(p->protected_region_count, ==, 2);
    g_assert_cmphex(p->protected_regions[1].size, ==, 0x2000);
    virt_drtm_params_free(p);

    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 3, 0);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
}

static void test_table_header_and_fetch(void)
{
    Fixture f;

    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    f.table_readable = 23;
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    st16(f.table, 2);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    st16(f.table + 2, 1);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    f.nonram_start = TABLE_ADDR;
    f.nonram_size = 24;
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    st64(f.params + 80, 25);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
    fixture_init(&f);
    enable_table(&f, 2);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    set_region(&f, 1, DCE_ADDR, 1, 0);
    {
        VirtDRTMCapabilities caps = all_caps;
        const VirtDRTMParameters *result = NULL;

        caps.maximum_protected_regions = 1;
        g_assert_cmpint(decode(&f, &caps, &result), ==,
                        VIRT_DRTM_MEM_PROTECT_INVALID);
    }
}

static void test_table_parameter_pair_and_limits(void)
{
    Fixture f;
    VirtDRTMCapabilities caps = all_caps;

    fixture_init(&f);
    st32(f.params + 4, BIT(3));
    st64(f.params + 72, TABLE_ADDR);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);

    fixture_init(&f);
    st32(f.params + 4, BIT(3));
    st64(f.params + 80, 8);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);

    fixture_init(&f);
    st32(f.params + 4, BIT(3));
    st64(f.params + 72, TABLE_ADDR);
    st64(f.params + 80, 7);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);

    fixture_init(&f);
    st32(f.params + 4, BIT(3));
    st64(f.params + 72, TABLE_ADDR);
    st64(f.params + 80, 73);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);

    fixture_init(&f);
    enable_table(&f, 0);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);

    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    caps.maximum_protected_regions = 0;
    expect_status_caps(&f, &caps, VIRT_DRTM_MEM_PROTECT_INVALID);
}

static void test_table_count_size_mismatch(void)
{
    Fixture f;

    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    st32(f.table + 4, 0);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);

    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    st32(f.table + 4, 2);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);

    fixture_init(&f);
    enable_table(&f, 0);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
}

static void test_table_descriptor_rules(void)
{
    Fixture f;

    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR + 1, 4, 0);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 0, 0);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 1);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4 | BIT_ULL(57), 0);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
    fixture_init(&f);
    enable_table(&f, 2);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    set_region(&f, 1, 0x30000, 1, 0);
    f.nonram_start = 0x30000;
    f.nonram_size = 0x1000;
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, UINT64_MAX & ~0xfffULL, 2, 0);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);

    for (unsigned int bit = 57; bit < 64; bit++) {
        fixture_init(&f);
        enable_table(&f, 1);
        set_region(&f, 0, DLME_ADDR, 4 | BIT_ULL(bit), 0);
        expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);
    }

    /* Bits[56:55] are applicable only to type 1; type 0 ignores them. */
    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4 | (3ULL << 55), 0);
    expect_status(&f, VIRT_DRTM_PARAM_SUCCESS);
}

static void test_table_overlap(void)
{
    Fixture f;

    fixture_init(&f);
    enable_table(&f, 2);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    set_region(&f, 1, DLME_ADDR + 0x3000, 1, 0);
    expect_status(&f, VIRT_DRTM_MEM_PROTECT_INVALID);

    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    st64(f.params + 72, DLME_ADDR);
    expect_status(&f, VIRT_DRTM_INVALID_PARAMETERS);

    fixture_init(&f);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    st64(f.params + 72, UINT64_MAX & ~0xfffULL);
    st64(f.params + 80, 0x2008);
    {
        VirtDRTMCapabilities caps = all_caps;

        caps.maximum_protected_regions = 512;
        expect_status_caps(&f, &caps, VIRT_DRTM_INVALID_PARAMETERS);
    }
}

static void test_dce_table_overlap(void)
{
    Fixture f;
    VirtDRTMCapabilities caps = all_caps;

    fixture_init(&f);
    enable_dce(&f, &caps, TABLE_ADDR, 0x1000);
    enable_table(&f, 2);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    set_region(&f, 1, TABLE_ADDR, 1, 0);
    expect_status_caps(&f, &caps, VIRT_DRTM_INVALID_PARAMETERS);
}

static void test_sorted_owned_single_snapshot(void)
{
    Fixture f;
    const VirtDRTMParameters *p;

    fixture_init(&f);
    enable_table(&f, 2);
    set_region(&f, 0, DLME_ADDR + 0x2000, 2, 0);
    set_region(&f, 1, DLME_ADDR, 2, 0);
    f.poison_table_after_read = true;
    g_assert_cmpint(decode(&f, &all_caps, &p), ==, VIRT_DRTM_PARAM_SUCCESS);
    g_assert_cmpuint(f.params_reads, ==, 1);
    g_assert_cmpuint(f.table_reads, ==, 1);
    g_assert_cmphex(p->protected_regions[0].address, ==, DLME_ADDR);
    g_assert_cmphex(p->protected_regions[1].address, ==,
                    DLME_ADDR + 0x2000);

    memset(f.params, 0xa5, sizeof(f.params));
    memset(f.table, 0xa5, sizeof(f.table));
    g_assert_cmphex(p->dlme_address, ==, DLME_ADDR);
    g_assert_cmphex(p->protected_regions[0].size, ==, 0x2000);
    virt_drtm_params_free(p);
}

static void test_bounded_wire_bit_mutations(void)
{
    Fixture baseline;

    fixture_init(&baseline);
    for (size_t byte = 0; byte < sizeof(baseline.params); byte++) {
        for (unsigned int bit = 0; bit < 8; bit++) {
            Fixture f = baseline;
            const VirtDRTMParameters *p = NULL;
            VirtDRTMParamStatus status;

            f.params[byte] ^= BIT(bit);
            status = decode(&f, &all_caps, &p);
            g_assert_true(status == VIRT_DRTM_PARAM_SUCCESS ||
                          status == VIRT_DRTM_INVALID_PARAMETERS ||
                          status == VIRT_DRTM_MEM_PROTECT_INVALID);
            virt_drtm_params_free(p);
        }
    }

    fixture_init(&baseline);
    enable_table(&baseline, 2);
    set_region(&baseline, 0, DLME_ADDR, 2, 0);
    set_region(&baseline, 1, DLME_ADDR + 0x2000, 2, 0);
    for (size_t byte = 0; byte < 40; byte++) {
        for (unsigned int bit = 0; bit < 8; bit++) {
            Fixture f = baseline;
            const VirtDRTMParameters *p = NULL;
            VirtDRTMParamStatus status;

            f.table[byte] ^= BIT(bit);
            status = decode(&f, &all_caps, &p);
            g_assert_true(status == VIRT_DRTM_PARAM_SUCCESS ||
                          status == VIRT_DRTM_MEM_PROTECT_INVALID);
            virt_drtm_params_free(p);
        }
    }
}

static void test_table_covers_dce(void)
{
    Fixture f;
    VirtDRTMCapabilities caps = all_caps;

    caps.minimum_dce_pages = 1;

    fixture_init(&f);
    st64(f.params + 56, DCE_ADDR);
    st64(f.params + 64, 0x1000);
    enable_table(&f, 1);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    expect_status_caps(&f, &caps, VIRT_DRTM_MEM_PROTECT_INVALID);

    fixture_init(&f);
    st64(f.params + 56, DCE_ADDR);
    st64(f.params + 64, 0x1000);
    enable_table(&f, 2);
    set_region(&f, 0, DLME_ADDR, 4, 0);
    set_region(&f, 1, DCE_ADDR, 1, 0);
    expect_status_caps(&f, &caps, VIRT_DRTM_PARAM_SUCCESS);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/virt-drtm-params/valid-complete", test_valid_complete);
    g_test_add_func("/virt-drtm-params/parameter-fetch", test_parameter_fetch);
    g_test_add_func("/virt-drtm-params/revision-reserved",
                    test_revision_reserved);
    g_test_add_func("/virt-drtm-params/reserved-bit-mutations",
                    test_reserved_bit_mutations);
    g_test_add_func("/virt-drtm-params/features", test_features);
    g_test_add_func("/virt-drtm-params/capability-sizes",
                    test_capability_sizes);
    g_test_add_func("/virt-drtm-params/dlme-boundaries", test_dlme_boundaries);
    g_test_add_func("/virt-drtm-params/dlme-alignment-ram",
                    test_dlme_alignment_and_ram);
    g_test_add_func("/virt-drtm-params/dce-pair-overlap",
                    test_dce_pair_and_overlap);
    g_test_add_func("/virt-drtm-params/dce-range-validation",
                    test_dce_range_validation);
    g_test_add_func("/virt-drtm-params/adjacent-parameter-ranges",
                    test_adjacent_parameter_ranges);
    g_test_add_func("/virt-drtm-params/table-valid-coverage",
                    test_valid_table_and_coverage);
    g_test_add_func("/virt-drtm-params/table-header-fetch",
                    test_table_header_and_fetch);
    g_test_add_func("/virt-drtm-params/table-parameter-pair-limits",
                    test_table_parameter_pair_and_limits);
    g_test_add_func("/virt-drtm-params/table-count-size",
                    test_table_count_size_mismatch);
    g_test_add_func("/virt-drtm-params/table-descriptors",
                    test_table_descriptor_rules);
    g_test_add_func("/virt-drtm-params/table-overlap", test_table_overlap);
    g_test_add_func("/virt-drtm-params/dce-table-overlap",
                    test_dce_table_overlap);
    g_test_add_func("/virt-drtm-params/sorted-owned-snapshot",
                    test_sorted_owned_single_snapshot);
    g_test_add_func("/virt-drtm-params/bounded-wire-bit-mutations",
                    test_bounded_wire_bit_mutations);
    g_test_add_func("/virt-drtm-params/table-covers-dce",
                    test_table_covers_dce);
    return g_test_run();
}
