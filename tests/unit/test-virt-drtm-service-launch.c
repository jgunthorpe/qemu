/*
 * Arm virt DRTM production launch assembly tests
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/bswap.h"
#include "qemu/bitops.h"
#include "qemu/main-loop.h"
#include "hw/arm/virt-drtm.h"
#include "hw/acpi/tpm.h"
#include "hw/tpm/tpm_tis.h"
#include "system/tpm_util.h"

#include "../../hw/arm/virt-drtm-service-launch-internal.h"
#include "../../hw/arm/virt-drtm-features-internal.h"

#define GUEST_BASE UINT64_C(0x100000)
#define GUEST_SIZE 0x40000
#define DLME_SIZE  0x20000
#define PARAMS_ADDRESS (GUEST_BASE + 0x21000)

#define TYPE_TEST_SERVICE_TPM "test-service-tpm-tis"
OBJECT_DECLARE_SIMPLE_TYPE(TestServiceTPM, TEST_SERVICE_TPM)

struct TestServiceTPM {
    Object parent;
    TPMState state;
    TPMBackend backend;
};

/* The TIS common model calls these backend entry points from its MMIO path. */
bool tpm_backend_had_startup_error(TPMBackend *be)
{
    return false;
}

bool tpm_backend_get_tpm_established_flag(TPMBackend *be)
{
    return false;
}

int tpm_backend_reset_tpm_established_flag(TPMBackend *be, uint8_t locality)
{
    return 0;
}

TPMVersion tpm_backend_get_tpm_version(TPMBackend *be)
{
    return TPM_VERSION_2_0;
}

size_t tpm_backend_get_buffer_size(TPMBackend *be)
{
    return TPM_TIS_BUFFER_MAX;
}

void tpm_backend_deliver_request(TPMBackend *be, TPMBackendCmd *cmd)
{
    g_assert_not_reached();
}

void tpm_backend_finish_sync(TPMBackend *be)
{
    g_assert_not_reached();
}

bool tpm_backend_finish_sync_timeout(TPMBackend *be, unsigned int timeout_ms)
{
    g_assert_not_reached();
}

void tpm_backend_cancel_cmd(TPMBackend *be)
{
    g_assert_not_reached();
}

void tpm_backend_reset(TPMBackend *be)
{
}

bool tpm_backend_drtm_hash(TPMBackend *be,
                           TPMBackendDRTMHashOperation operation,
                           const uint8_t *data, size_t data_size,
                           Error **errp)
{
    g_assert_not_reached();
}

bool tpm_backend_supports_drtm_hash(TPMBackend *be)
{
    return true;
}

int tpm_backend_startup_tpm(TPMBackend *be, size_t buffer_size)
{
    return 0;
}

void tpm_ppi_reset(TPMPPI *tpmppi)
{
}

void tpm_util_show_buffer(const unsigned char *buffer, size_t buffer_size,
                          const char *string)
{
}

static TPMVersion test_service_tpm_version(TPMIf *ti)
{
    return TPM_VERSION_2_0;
}

static bool test_service_tpm_no_active(TPMIf *ti, bool *no_active,
                                       Error **errp)
{
    return tpm_tis_drtm_no_active_locality(
        &TEST_SERVICE_TPM(ti)->state, no_active, errp);
}

static void test_service_tpm_iface_init(ObjectClass *klass, const void *data)
{
    TPMIfClass *tc = TPM_IF_CLASS(klass);

    tc->get_version = test_service_tpm_version;
    tc->drtm_no_active_locality = test_service_tpm_no_active;
}

static void test_service_tpm_init(Object *obj)
{
    TestServiceTPM *tpm = TEST_SERVICE_TPM(obj);
    TPMState *s = &tpm->state;

    s->be_driver = &tpm->backend;
    s->be_buffer_size = TPM_TIS_BUFFER_MAX;
    s->active_locty = TPM_TIS_NO_LOCALITY;
    s->next_locty = TPM_TIS_NO_LOCALITY;
    s->aborting_locty = TPM_TIS_NO_LOCALITY;
    for (unsigned int i = 0; i < TPM_TIS_NUM_LOCALITIES; i++) {
        s->loc[i].access = TPM_TIS_ACCESS_TPM_REG_VALID_STS;
    }
}

static const TypeInfo test_service_tpm_info = {
    .name = TYPE_TEST_SERVICE_TPM,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(TestServiceTPM),
    .instance_init = test_service_tpm_init,
    .class_init = test_service_tpm_iface_init,
    .interfaces = (const InterfaceInfo[]) {
        { TYPE_TPM_IF },
        { }
    },
};

static const TypeInfo test_tpm_if_info = {
    .name = TYPE_TPM_IF,
    .parent = TYPE_INTERFACE,
    .class_size = sizeof(TPMIfClass),
};

typedef struct Fixture {
    VirtDRTMState service;
    uint8_t guest[GUEST_SIZE];
    GString *sequence;
    unsigned int writes;
    unsigned int enters;
    unsigned int resets;
    bool effects_started;
    VirtDRTMResult map_result;
    size_t map_count_override;
    uint64_t write_address;
    size_t write_size;
    bool probe_success;
    bool no_active;
    TPMIf *tpm_if;
} Fixture;
static unsigned int allocations_before_failure;

static void *test_alloc(size_t size)
{
    if (!allocations_before_failure) {
        return NULL;
    }
    allocations_before_failure--;
    return g_try_malloc(size);
}

static uint8_t *guest_pointer(Fixture *f, uint64_t address, size_t size)
{
    uint64_t offset;

    if (address < GUEST_BASE) {
        return NULL;
    }
    offset = address - GUEST_BASE;
    if (offset > sizeof(f->guest) || size > sizeof(f->guest) - offset) {
        return NULL;
    }
    return f->guest + offset;
}

static bool test_read(void *opaque, uint64_t address, void *buffer,
                      size_t size)
{
    Fixture *f = opaque;
    uint8_t *source = guest_pointer(f, address, size);

    g_assert_false(f->effects_started);
    if (!source) {
        return false;
    }
    memcpy(buffer, source, size);
    return true;
}

static bool test_is_ram(void *opaque, uint64_t address, uint64_t size)
{
    return size <= SIZE_MAX && guest_pointer(opaque, address, size);
}

static VirtDRTMResult test_snapshot_map(void *opaque,
                                        VirtDRTMMemoryRegion **regions,
                                        size_t *count)
{
    Fixture *f = opaque;
    VirtDRTMMemoryRegion map[] = {
        { GUEST_BASE, GUEST_SIZE, VIRT_DRTM_MEMORY_NORMAL_CACHED, 3 },
        { 0x200000, 0x1000, VIRT_DRTM_MEMORY_MMIO, 0 },
        { 0x300000, 0x1000, VIRT_DRTM_MEMORY_NON_VOLATILE, 0 },
    };

    if (f->map_result != VIRT_DRTM_SUCCESS) {
        return f->map_result;
    }
    if (f->map_count_override) {
        *regions = g_new0(VirtDRTMMemoryRegion, f->map_count_override);
        *count = f->map_count_override;
        return VIRT_DRTM_SUCCESS;
    }
    *regions = g_memdup2(map, sizeof(map));
    *count = ARRAY_SIZE(map);
    return VIRT_DRTM_SUCCESS;
}

static bool test_no_active(void *opaque, bool *no_active, Error **errp)
{
    Fixture *f = opaque;

    g_string_append_c(f->sequence, 'P');
    if (!f->probe_success) {
        error_setg(errp, "injected locality probe failure");
        return false;
    }
    *no_active = f->no_active;
    return true;
}

static bool test_real_tis_no_active(void *opaque, bool *no_active,
                                    Error **errp)
{
    Fixture *f = opaque;

    g_string_append_c(f->sequence, 'P');
    return tpm_drtm_no_active_locality(f->tpm_if, no_active, errp);
}

static bool test_prepare(void *opaque,
                         const VirtDRTMMeasurementManifest *manifest,
                         Error **errp)
{
    Fixture *f = opaque;

    g_assert_nonnull(manifest);
    g_string_append_c(f->sequence, 'T');
    return true;
}

static bool test_open(void *opaque, Error **errp)
{
    Fixture *f = opaque;

    f->effects_started = true;
    g_string_append_c(f->sequence, 'O');
    return true;
}

static VirtDRTMTPMResult tpm_step(void *opaque, char step)
{
    g_string_append_c(((Fixture *)opaque)->sequence, step);
    return (VirtDRTMTPMResult) { .status = VIRT_DRTM_TPM_OK };
}

static VirtDRTMTPMResult test_hash(
    void *opaque, const VirtDRTMMeasurementManifest *manifest, Error **errp)
{
    return tpm_step(opaque, 'H');
}

static VirtDRTMTPMResult test_dcrtm(
    void *opaque, const VirtDRTMMeasurementManifest *manifest, Error **errp)
{
    return tpm_step(opaque, 'R');
}

static VirtDRTMTPMResult test_dce(
    void *opaque, const VirtDRTMMeasurementManifest *manifest, Error **errp)
{
    return tpm_step(opaque, 'E');
}

static bool test_write(void *opaque, uint64_t address, const uint8_t *data,
                       size_t size, Error **errp)
{
    Fixture *f = opaque;
    uint8_t *destination = guest_pointer(f, address, size);

    g_assert_nonnull(destination);
    g_assert_cmphex(address, ==, GUEST_BASE + 0x1000);
    g_assert_cmpuint(size, <=, DLME_SIZE - 0x1000);
    f->writes++;
    f->write_address = address;
    f->write_size = size;
    memcpy(destination, data, size);
    g_string_append_c(f->sequence, 'W');
    return true;
}

static bool test_close(void *opaque, TPMDRTMLocalityCloseResult *result,
                       Error **errp)
{
    g_string_append_c(((Fixture *)opaque)->sequence, 'C');
    *result = TPM_DRTM_LOCALITY_CLOSED;
    return true;
}

static bool test_activate(void *opaque, Error **errp)
{
    g_string_append_c(((Fixture *)opaque)->sequence, 'A');
    return true;
}

static bool test_enter(void *opaque, uint64_t dlme_address,
                       uint64_t data_offset, uint64_t entry_address,
                       Error **errp)
{
    Fixture *f = opaque;

    g_assert_cmphex(dlme_address, ==, GUEST_BASE);
    g_assert_cmphex(data_offset, ==, 0x1000);
    g_assert_cmphex(entry_address, ==, GUEST_BASE + 8);
    f->enters++;
    g_string_append_c(f->sequence, 'I');
    return true;
}

static void test_reset(void *opaque)
{
    Fixture *f = opaque;

    f->resets++;
    g_string_append_c(f->sequence, 'X');
}

static VirtDRTMServiceLaunchOps test_ops(void)
{
    return (VirtDRTMServiceLaunchOps) {
        .read = test_read,
        .is_ram = test_is_ram,
        .alloc = test_alloc,
        .snapshot_address_map = test_snapshot_map,
        .prepare_tpm = test_prepare,
        .launch = {
            .no_active_locality = test_no_active,
            .open_localities = test_open,
            .hash_dce = test_hash,
            .extend_dcrtm = test_dcrtm,
            .extend_dce = test_dce,
            .write = test_write,
            .close_locality3 = test_close,
            .activate_locality2 = test_activate,
            .enter_dlme = test_enter,
            .request_cold_reset = test_reset,
        },
        .debug_or_trace_enabled = true,
        .nonsecure_lifecycle = false,
    };
}

static void install_parameters(Fixture *f)
{
    uint8_t *p = guest_pointer(f, PARAMS_ADDRESS, VIRT_DRTM_PARAMETERS_SIZE);

    stw_le_p(p, 2);
    stl_le_p(p + 4, BIT(7));
    stq_le_p(p + 8, GUEST_BASE);
    stq_le_p(p + 16, DLME_SIZE);
    stq_le_p(p + 24, 0);
    stq_le_p(p + 32, 8);
    stq_le_p(p + 40, 16);
    stq_le_p(p + 48, 0x1000);
    for (size_t i = 0; i < 16; i++) {
        f->guest[i] = 0x80 + i;
    }
}

static Fixture *fixture_new(void)
{
    Fixture *f = g_new0(Fixture, 1);

    f->sequence = g_string_new(NULL);
    allocations_before_failure = UINT_MAX;
    f->service.enabled = true;
    f->service.tpm_ready = true;
    f->service.firmware_hash_algorithm = 0x000b;
    f->service.active_banks[0] = 0x000b;
    f->service.active_bank_count = 1;
    f->probe_success = true;
    f->no_active = true;
    virt_drtm_workflow_init(&f->service.workflow);
    g_assert_true(virt_drtm_tcb_init(&f->service.tcb_hashes, 0x000b,
                                    VIRT_DRTM_TCB_HASH_CAPACITY));
    install_parameters(f);
    return f;
}

static void add_mutable_tcb(Fixture *f, bool lock)
{
    uint8_t table[44] = { 0 };

    stw_le_p(table, 1);
    stw_le_p(table + 2, 1);
    stw_le_p(table + 4, 0x000b);
    stl_le_p(table + 8, 0x41424344);
    memset(table + 12, 0x5a, 32);
    g_assert_cmpint(virt_drtm_tcb_set(&f->service.tcb_hashes,
                                      table, sizeof(table)).status,
                    ==, VIRT_DRTM_TCB_SUCCESS);
    if (lock) {
        g_assert_cmpint(virt_drtm_tcb_lock(&f->service.tcb_hashes), ==,
                        VIRT_DRTM_TCB_SUCCESS);
    }
}

static void fixture_free(Fixture *f)
{
    g_string_free(f->sequence, true);
    g_free(f);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(Fixture, fixture_free)

static void test_success(void)
{
    g_autoptr(Fixture) f = fixture_new();
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMLaunchResult result;
    uint64_t event_size, tcb_offset;

    add_mutable_tcb(f, true);
    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f,
        &error_abort);
    uint8_t *data = guest_pointer(f, GUEST_BASE + 0x1000, f->write_size);

    g_assert_cmpint(result.result, ==, VIRT_DRTM_SUCCESS);
    g_assert_true(result.committed);
    g_assert_true(result.non_returning);
    g_assert_cmpstr(f->sequence->str, ==, "PTPOHREWCAI");
    g_assert_cmpuint(f->writes, ==, 1);
    g_assert_cmphex(f->write_address, ==, GUEST_BASE + 0x1000);
    g_assert_cmpuint(f->enters, ==, 1);
    g_assert_cmpuint(f->resets, ==, 0);
    g_assert_cmpuint(lduw_le_p(data), ==, 1);
    g_assert_cmpuint(ldq_le_p(data + 24), ==, 56); /* Three map entries. */
    g_assert_cmpuint(ldl_le_p(data + 88 + 4), ==, 3);
    g_assert_cmpuint(ldq_le_p(data + 88 + 16) >> 52 & 7, ==,
                     VIRT_DRTM_MEMORY_NORMAL_CACHED);
    g_assert_cmpuint(ldq_le_p(data + 88 + 32) >> 52 & 7, ==,
                     VIRT_DRTM_MEMORY_MMIO);
    g_assert_cmpuint(ldq_le_p(data + 88 + 48) >> 52 & 7, ==,
                     VIRT_DRTM_MEMORY_NON_VOLATILE);
    g_assert_cmpuint(ldq_le_p(data + 40), ==, 44);
    event_size = ldq_le_p(data + 32);
    tcb_offset = 64 + 24 + 56 + event_size;
    g_assert_cmpuint(lduw_le_p(data + tcb_offset + 2), ==, 1);
    g_assert_cmphex((uint32_t)ldl_le_p(data + tcb_offset + 8), ==,
                    UINT32_C(0xc1424344));
}

static void test_success_without_tcb_hashes(void)
{
    g_autoptr(Fixture) f = fixture_new();
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMLaunchResult result;
    uint8_t *data;

    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f, &error_abort);
    data = guest_pointer(f, GUEST_BASE + 0x1000, f->write_size);

    g_assert_cmpint(result.result, ==, VIRT_DRTM_SUCCESS);
    g_assert_true(result.committed);
    g_assert_true(result.non_returning);
    g_assert_cmpstr(f->sequence->str, ==, "PTPOHREWCAI");
    g_assert_cmpuint(ldq_le_p(data + 40), ==, 0);
    g_assert_cmpuint(ldq_le_p(data + 48), ==, 0);
}

static void test_returnable_invalid_parameters(void)
{
    g_autoptr(Fixture) f = fixture_new();
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMLaunchResult result;

    stw_le_p(guest_pointer(f, PARAMS_ADDRESS, 2), 1);
    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f,
        &error_abort);
    g_assert_cmpint(result.result, ==, VIRT_DRTM_INVALID_PARAMETERS);
    g_assert_false(result.committed);
    g_assert_cmpstr(f->sequence->str, ==, "P");
    g_assert_cmpuint(f->writes + f->enters + f->resets, ==, 0);
    g_assert_cmpint(f->service.workflow.phase, ==, VIRT_DRTM_PHASE_READY);
}

static void test_region_protection_is_not_supported(void)
{
    g_autoptr(Fixture) f = fixture_new();
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMLaunchResult result;
    uint8_t *parameters = guest_pointer(f, PARAMS_ADDRESS,
                                        VIRT_DRTM_PARAMETERS_SIZE);

    stl_le_p(parameters + 4, BIT(3) | BIT(7));
    stq_le_p(parameters + 72, GUEST_BASE + 0x20000);
    stq_le_p(parameters + 80, 8);
    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f, &error_abort);
    g_assert_cmpint(result.result, ==, VIRT_DRTM_INVALID_PARAMETERS);
    g_assert_false(result.committed);
    g_assert_cmpstr(f->sequence->str, ==, "P");
    g_assert_cmpuint(f->writes + f->enters + f->resets, ==, 0);
}

static void set_repeat_workflow_with_stale_active_locality(Fixture *f)
{
    f->service.workflow.phase = VIRT_DRTM_PHASE_DLME;
    f->service.workflow.locality[1] = VIRT_DRTM_LOCALITY_OPEN;
    f->service.workflow.locality[2] = VIRT_DRTM_LOCALITY_ACTIVE;
    f->service.workflow.locality[3] = VIRT_DRTM_LOCALITY_CLOSED;
    f->service.workflow.protection = VIRT_DRTM_PROTECTION_NONE;
    f->service.workflow.protection_release_available = false;
    f->service.workflow.secure_interrupts =
        VIRT_DRTM_SECURE_INTERRUPTS_REENABLED;
    f->service.workflow.launch_sequence = 1;
}

static void test_repeat_reconciles_probed_relinquish(void)
{
    g_autoptr(Fixture) f = fixture_new();
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMLaunchResult result;

    set_repeat_workflow_with_stale_active_locality(f);
    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f, &error_abort);

    g_assert_cmpint(result.result, ==, VIRT_DRTM_SUCCESS);
    g_assert_true(result.committed);
    g_assert_true(result.non_returning);
    g_assert_cmpstr(f->sequence->str, ==, "PTPOHREWCAI");
    g_assert_cmpuint(f->service.workflow.launch_sequence, ==, 2);
    g_assert_cmpint(f->service.workflow.phase, ==, VIRT_DRTM_PHASE_DLME);
    g_assert_cmpint(f->service.workflow.locality[2], ==,
                    VIRT_DRTM_LOCALITY_ACTIVE);
}

static void test_repeat_reconciles_real_tis_mmio_relinquish(void)
{
    g_autoptr(Fixture) f = fixture_new();
    TestServiceTPM *tpm = TEST_SERVICE_TPM(
        object_new(TYPE_TEST_SERVICE_TPM));
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMLaunchResult result;
    bool no_active = false;

    f->tpm_if = TPM_IF(tpm);
    ops.launch.no_active_locality = test_real_tis_no_active;
    set_repeat_workflow_with_stale_active_locality(f);

    g_assert_true(tpm_tis_enable_drtm(&tpm->state, &error_abort));
    g_assert_true(tpm_tis_drtm_open_localities(&tpm->state, &error_abort));
    g_assert_true(tpm_tis_drtm_activate_locality2(&tpm->state, &error_abort));
    g_assert_true(tpm_drtm_no_active_locality(f->tpm_if, &no_active,
                                              &error_abort));
    g_assert_false(no_active);

    /* Model the DLME's ordinary guest write to relinquish locality 2. */
    tpm_tis_write_data(&tpm->state,
                       (2 << TPM_TIS_LOCALITY_SHIFT) | TPM_TIS_REG_ACCESS,
                       TPM_TIS_ACCESS_ACTIVE_LOCALITY, 1);
    g_assert_cmpuint(tpm->state.active_locty, ==, TPM_TIS_NO_LOCALITY);

    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f, &error_abort);

    g_assert_cmpint(result.result, ==, VIRT_DRTM_SUCCESS);
    g_assert_true(result.committed);
    g_assert_true(result.non_returning);
    g_assert_cmpstr(f->sequence->str, ==, "PTPOHREWCAI");
    g_assert_cmpuint(f->service.workflow.launch_sequence, ==, 2);
    g_assert_cmpint(f->service.workflow.phase, ==, VIRT_DRTM_PHASE_DLME);
    g_assert_cmpint(f->service.workflow.locality[2], ==,
                    VIRT_DRTM_LOCALITY_ACTIVE);

    object_unref(OBJECT(tpm));
}

static void test_probe_failure_does_not_reconcile(void)
{
    for (unsigned int i = 0; i < 2; i++) {
        g_autoptr(Fixture) f = fixture_new();
        VirtDRTMServiceLaunchOps ops = test_ops();
        VirtDRTMLaunchResult result;
        Error *err = NULL;

        set_repeat_workflow_with_stale_active_locality(f);
        f->no_active = false;
        f->probe_success = i != 0;
        result = virt_drtm_service_launch_with_ops(
            &f->service, PARAMS_ADDRESS, true, true, true,
            VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f, &err);

        g_assert_cmpint(result.result, ==,
                        i ? VIRT_DRTM_DENIED : VIRT_DRTM_TPM_ERROR);
        g_assert_false(result.committed);
        g_assert_cmpstr(f->sequence->str, ==, "P");
        g_assert_cmpint(f->service.workflow.phase, ==,
                        VIRT_DRTM_PHASE_DLME);
        g_assert_cmpint(f->service.workflow.locality[2], ==,
                        VIRT_DRTM_LOCALITY_ACTIVE);
        if (i) {
            g_assert_null(err);
        } else {
            g_assert_nonnull(err);
            error_free(err);
        }
    }
}

static void test_reconciliation_preserves_preflight_failure(void)
{
    g_autoptr(Fixture) f = fixture_new();
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMLaunchResult result;

    set_repeat_workflow_with_stale_active_locality(f);
    stw_le_p(guest_pointer(f, PARAMS_ADDRESS, 2), 1);
    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f, &error_abort);

    g_assert_cmpint(result.result, ==, VIRT_DRTM_INVALID_PARAMETERS);
    g_assert_false(result.committed);
    g_assert_cmpstr(f->sequence->str, ==, "P");
    g_assert_cmpint(f->service.workflow.phase, ==, VIRT_DRTM_PHASE_DLME);
    g_assert_cmpint(f->service.workflow.locality[2], ==,
                    VIRT_DRTM_LOCALITY_RELINQUISHED);
    g_assert_cmpuint(f->service.workflow.launch_sequence, ==, 1);
}

static void test_unlocked_tcb_remediates(void)
{
    g_autoptr(Fixture) f = fixture_new();
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMLaunchResult result;

    add_mutable_tcb(f, false);
    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f,
        &error_abort);
    g_assert_true(result.committed);
    g_assert_true(result.reset_requested);
    g_assert_cmpint(result.stage, ==, VIRT_DRTM_LAUNCH_TCB_LOCK);
    g_assert_cmpstr(f->sequence->str, ==, "PTPOHREX");
    g_assert_cmpuint(f->writes + f->enters, ==, 0);
    g_assert_cmpuint(f->resets, ==, 1);
}

static void test_address_map_capacity_is_enforced(void)
{
    g_autoptr(Fixture) f = fixture_new();
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMLaunchResult result;

    f->map_count_override = VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS + 1;
    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f, &error_abort);
    g_assert_cmpint(result.result, ==, VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
    g_assert_false(result.committed);
    g_assert_cmpstr(f->sequence->str, ==, "P");
    g_assert_cmpuint(f->writes + f->enters + f->resets, ==, 0);
}

static void test_advertised_minimum_is_enforced(void)
{
    g_autoptr(Fixture) f = fixture_new();
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMCapabilities capabilities;
    VirtDRTMLaunchResult result;
    uint32_t supported_features;
    uint8_t *parameters = guest_pointer(f, PARAMS_ADDRESS,
                                        VIRT_DRTM_PARAMETERS_SIZE);

    g_assert_true(virt_drtm_features_launch_capabilities(
        &f->service, VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &capabilities,
        &supported_features));
    g_assert_cmpuint(capabilities.minimum_dlme_data_pages, >, 1);
    stq_le_p(parameters + 16,
             (uint64_t)capabilities.minimum_dlme_data_pages *
             VIRT_DRTM_PAGE_SIZE);
    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f, &error_abort);
    g_assert_cmpint(result.result, ==, VIRT_DRTM_INVALID_PARAMETERS);
    g_assert_false(result.committed);
    g_assert_cmpstr(f->sequence->str, ==, "P");
}

static void test_address_map_resource_failure(void)
{
    g_autoptr(Fixture) f = fixture_new();
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMLaunchResult result;

    f->map_result = VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE;
    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f,
        &error_abort);
    g_assert_cmpint(result.result, ==,
                    VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
    g_assert_false(result.committed);
    g_assert_cmpstr(f->sequence->str, ==, "P");
    g_assert_cmpuint(f->writes + f->enters + f->resets, ==, 0);
}

static void test_tcb_snapshot_resource_failure(void)
{
    g_autoptr(Fixture) f = fixture_new();
    VirtDRTMServiceLaunchOps ops = test_ops();
    VirtDRTMLaunchResult result;

    add_mutable_tcb(f, true);
    /* The DLME image snapshot succeeds, then TCB snapshot allocation fails. */
    allocations_before_failure = 1;
    result = virt_drtm_service_launch_with_ops(
        &f->service, PARAMS_ADDRESS, true, true, true,
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, f,
        &error_abort);
    g_assert_cmpint(result.result, ==,
                    VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE);
    g_assert_false(result.committed);
    g_assert_cmpstr(f->sequence->str, ==, "P");
    g_assert_cmpuint(f->writes + f->enters + f->resets, ==, 0);
}

int main(int argc, char **argv)
{
    type_register_static(&test_tpm_if_info);
    type_register_static(&test_service_tpm_info);
    g_test_init(&argc, &argv, NULL);
    rust_bql_mock_lock();
    g_test_add_func("/virt-drtm-service/success", test_success);
    g_test_add_func("/virt-drtm-service/success-without-tcb",
                    test_success_without_tcb_hashes);
    g_test_add_func("/virt-drtm-service/returnable-invalid",
                    test_returnable_invalid_parameters);
    g_test_add_func("/virt-drtm-service/region-protection-unsupported",
                    test_region_protection_is_not_supported);
    g_test_add_func("/virt-drtm-service/repeat-probed-relinquish",
                    test_repeat_reconciles_probed_relinquish);
    g_test_add_func("/virt-drtm-service/repeat-real-tis-mmio-relinquish",
                    test_repeat_reconciles_real_tis_mmio_relinquish);
    g_test_add_func("/virt-drtm-service/probe-no-reconcile",
                    test_probe_failure_does_not_reconcile);
    g_test_add_func("/virt-drtm-service/reconcile-preflight-failure",
                    test_reconciliation_preserves_preflight_failure);
    g_test_add_func("/virt-drtm-service/unlocked-tcb",
                    test_unlocked_tcb_remediates);
    g_test_add_func("/virt-drtm-service/address-map-capacity",
                    test_address_map_capacity_is_enforced);
    g_test_add_func("/virt-drtm-service/advertised-minimum",
                    test_advertised_minimum_is_enforced);
    g_test_add_func("/virt-drtm-service/address-map-resource-failure",
                    test_address_map_resource_failure);
    g_test_add_func("/virt-drtm-service/tcb-snapshot-resource-failure",
                    test_tcb_snapshot_resource_failure);
    return g_test_run();
}
