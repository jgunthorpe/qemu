/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/arm/virt-drtm-tcb.h"
#include "hw/arm/virt-drtm-tpm.h"
#include "qapi/error.h"
#include "qemu/bswap.h"

typedef struct Selection {
    uint16_t algorithm;
    uint8_t size;
    uint8_t bits[8];
} Selection;

typedef struct Fixture {
    Selection selections[5];
    size_t count;
    bool transport_failure;
    uint16_t tag;
    uint8_t more_data;
    uint32_t capability;
    uint32_t response_code;
    int size_adjustment;
    size_t calls;
} Fixture;

static bool forbidden_hash(void *opaque, uint8_t locality,
                           TPMBackendDRTMHashOperation operation,
                           const uint8_t *data, size_t data_size, Error **errp)
{
    g_assert_not_reached();
}

static bool capability_command(void *opaque, uint8_t locality,
                               const uint8_t *request, size_t request_size,
                               uint8_t *response, size_t *response_size,
                               Error **errp)
{
    Fixture *f = opaque;
    size_t size = f->response_code ? 10 : 19;
    unsigned int i;

    f->calls++;
    g_assert_cmpuint(locality, ==, 0);
    g_assert_cmpuint(request_size, ==, 22);
    g_assert_cmphex(lduw_be_p(request), ==, 0x8001);
    g_assert_cmpuint(ldl_be_p(request + 2), ==, request_size);
    g_assert_cmphex(ldl_be_p(request + 6), ==, 0x17a);
    g_assert_cmphex(ldl_be_p(request + 10), ==, 5);
    g_assert_cmpuint(ldl_be_p(request + 14), ==, 0);
    g_assert_cmpuint(ldl_be_p(request + 18), ==, 1);
    if (f->transport_failure) {
        error_setg(errp, "injected transport failure");
        return false;
    }

    for (i = 0; !f->response_code && i < f->count; i++) {
        size += 3 + f->selections[i].size;
    }
    g_assert_cmpuint(*response_size, >=, size + MAX(f->size_adjustment, 0));
    memset(response, 0, *response_size);
    stw_be_p(response, f->tag);
    stl_be_p(response + 6, f->response_code);
    if (!f->response_code) {
        size_t offset = 19;

        response[10] = f->more_data;
        stl_be_p(response + 11, f->capability);
        stl_be_p(response + 15, f->count);
        for (i = 0; i < f->count; i++) {
            stw_be_p(response + offset, f->selections[i].algorithm);
            response[offset + 2] = f->selections[i].size;
            memcpy(response + offset + 3, f->selections[i].bits,
                   f->selections[i].size);
            offset += 3 + f->selections[i].size;
        }
    }
    size += f->size_adjustment;
    stl_be_p(response + 2, size);
    *response_size = size;
    return true;
}

static const VirtDRTMTPMOps ops = {
    .hash = forbidden_hash,
    .command = capability_command,
};

static Selection active(uint16_t algorithm)
{
    Selection selection = {
        .algorithm = algorithm,
        .size = 3,
        /* PCR17 and PCR18 are bits 1 and 2 of byte 2. */
        .bits = { 0xff, 0xff, 0x06 },
    };

    return selection;
}

static Fixture fixture(void)
{
    Fixture f = {
        .tag = 0x8001,
        .capability = 5,
    };

    return f;
}

static VirtDRTMTPMBanks discover(Fixture *f, Error **errp)
{
    return virt_drtm_tpm_discover_banks(&ops, f, errp);
}

static void assert_response_error(Fixture *f)
{
    Error *err = NULL;
    VirtDRTMTPMBanks result = discover(f, &err);

    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_BANKS_RESPONSE_ERROR);
    g_assert_cmpuint(result.bank_count, ==, 0);
    g_assert_cmphex(result.selected_algorithm, ==, 0);
    g_assert_nonnull(err);
    error_free(err);
}

static void test_sha384_preference(void)
{
    Fixture f = fixture();
    VirtDRTMTPMBanks result;
    VirtDRTMTCBStore store;

    f.selections[0] = active(VIRT_DRTM_TPM_ALG_SHA512);
    f.selections[1] = active(VIRT_DRTM_TPM_ALG_SHA256);
    f.selections[2] = active(VIRT_DRTM_TPM_ALG_SHA384);
    f.count = 3;
    result = discover(&f, &error_abort);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_BANKS_OK);
    g_assert_cmpuint(result.bank_count, ==, 3);
    g_assert_cmphex(result.banks[0], ==, VIRT_DRTM_TPM_ALG_SHA512);
    g_assert_cmphex(result.selected_algorithm, ==,
                    VIRT_DRTM_TPM_ALG_SHA384);

    /* The result directly and safely configures the later TCB store. */
    g_assert_true(virt_drtm_tcb_init(&store, result.selected_algorithm, 4));
    store.count = 1;
    store.locked = true;
    virt_drtm_tcb_reset(&store);
    g_assert_cmphex(store.algorithm, ==, VIRT_DRTM_TPM_ALG_SHA384);
    g_assert_cmpuint(store.capacity, ==, 4);
    g_assert_cmpuint(store.count, ==, 0);
    g_assert_false(store.locked);
}

static void test_fallback_and_sha1(void)
{
    Fixture f = fixture();
    VirtDRTMTPMBanks result;

    f.selections[0] = active(VIRT_DRTM_TPM_ALG_SHA1);
    f.selections[1] = active(VIRT_DRTM_TPM_ALG_SHA256);
    f.count = 2;
    result = discover(&f, &error_abort);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_BANKS_OK);
    g_assert_cmphex(result.selected_algorithm, ==,
                    VIRT_DRTM_TPM_ALG_SHA256);

    f.selections[1] = active(VIRT_DRTM_TPM_ALG_SHA512);
    result = discover(&f, &error_abort);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_BANKS_OK);
    g_assert_cmphex(result.selected_algorithm, ==,
                    VIRT_DRTM_TPM_ALG_SHA512);
}

static void test_masks_and_inactive(void)
{
    Fixture f = fixture();
    VirtDRTMTPMBanks result;

    f.selections[0] = active(0x0012); /* Unsupported but unallocated SM3. */
    f.selections[0].size = 4;
    f.selections[1] = active(VIRT_DRTM_TPM_ALG_SHA256);
    memset(f.selections[0].bits, 0, sizeof(f.selections[0].bits));
    f.count = 2;
    result = discover(&f, &error_abort);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_BANKS_OK);
    g_assert_cmpuint(f.calls, ==, 1);
    g_assert_cmpuint(result.bank_count, ==, 1);
    g_assert_cmphex(result.banks[0], ==, VIRT_DRTM_TPM_ALG_SHA256);
}

static void test_missing_pcrs(void)
{
    Fixture f = fixture();

    f.selections[0] = active(VIRT_DRTM_TPM_ALG_SHA256);
    f.count = 1;
    f.selections[0].bits[2] = 0x04;
    assert_response_error(&f);
    f.selections[0].bits[2] = 0x02;
    assert_response_error(&f);
}

static void test_unknown_and_duplicate(void)
{
    Fixture f = fixture();

    f.selections[0] = active(0x0012);
    f.count = 1;
    assert_response_error(&f);

    f = fixture();
    f.selections[0] = active(VIRT_DRTM_TPM_ALG_SHA256);
    f.selections[1] = active(VIRT_DRTM_TPM_ALG_SHA256);
    f.count = 2;
    assert_response_error(&f);
}

static void test_malformed(void)
{
    Fixture f = fixture();

    f.selections[0] = active(VIRT_DRTM_TPM_ALG_SHA256);
    f.count = 1;
    f.more_data = 1;
    assert_response_error(&f);
    f.more_data = 2;
    assert_response_error(&f);

    f = fixture();
    f.selections[0] = active(VIRT_DRTM_TPM_ALG_SHA256);
    f.count = 1;
    f.capability = 6;
    assert_response_error(&f);
    f.capability = 5;
    f.tag = 0x8002;
    assert_response_error(&f);

    f = fixture();
    f.selections[0] = active(VIRT_DRTM_TPM_ALG_SHA256);
    f.selections[0].size = 2;
    f.count = 1;
    assert_response_error(&f);
    f.selections[0].size = 3;
    f.size_adjustment = -1;
    assert_response_error(&f);
    f.size_adjustment = 1;
    assert_response_error(&f);

    f = fixture();
    assert_response_error(&f);
}

static void test_transport_and_tpm_error(void)
{
    Fixture f = fixture();
    VirtDRTMTPMBanks result;
    Error *err = NULL;

    f.transport_failure = true;
    result = discover(&f, &err);
    g_assert_cmpint(result.status, ==,
                    VIRT_DRTM_TPM_BANKS_TRANSPORT_ERROR);
    g_assert_cmpuint(result.bank_count, ==, 0);
    g_assert_nonnull(err);
    error_free(err);

    f = fixture();
    f.response_code = 0x101;
    err = NULL;
    result = discover(&f, &err);
    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_BANKS_TPM_ERROR);
    g_assert_cmphex(result.response_code, ==, 0x101);
    g_assert_cmpuint(result.bank_count, ==, 0);
    g_assert_nonnull(err);
    error_free(err);
}

static void test_invalid(void)
{
    Error *err = NULL;
    VirtDRTMTPMBanks result = virt_drtm_tpm_discover_banks(NULL, NULL, &err);

    g_assert_cmpint(result.status, ==, VIRT_DRTM_TPM_BANKS_INVALID);
    g_assert_nonnull(err);
    error_free(err);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/virt-drtm-tpm-banks/sha384", test_sha384_preference);
    g_test_add_func("/virt-drtm-tpm-banks/fallback", test_fallback_and_sha1);
    g_test_add_func("/virt-drtm-tpm-banks/masks", test_masks_and_inactive);
    g_test_add_func("/virt-drtm-tpm-banks/missing-pcrs", test_missing_pcrs);
    g_test_add_func("/virt-drtm-tpm-banks/unknown-duplicate",
                    test_unknown_and_duplicate);
    g_test_add_func("/virt-drtm-tpm-banks/malformed", test_malformed);
    g_test_add_func("/virt-drtm-tpm-banks/errors", test_transport_and_tpm_error);
    g_test_add_func("/virt-drtm-tpm-banks/invalid", test_invalid);
    return g_test_run();
}
