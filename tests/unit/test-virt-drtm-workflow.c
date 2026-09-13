/*
 * Arm virt DRTM workflow model tests
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/arm/virt-drtm-workflow.h"
#include "hw/arm/virt-drtm-launch.h"

#define DLME_ADDRESS 0x40000000
#define DLME_SIZE    0x00400000
#define DATA_ADDRESS 0x40200000

typedef struct Fixture {
    VirtDRTMWorkflow workflow;
    VirtDRTMParameters parameters;
    VirtDRTMEventLogInput event;
    VirtDRTMDataInput data;
    VirtDRTMPreflightInput preflight;
    VirtDRTMMemoryRegion map;
    VirtDRTMMemoryRegion protected;
    VirtDRTMTCBHash hashes[5];
    uint16_t active_bank;
    uint8_t digests[5][32];
    uint8_t image[4096];
} Fixture;

static const uint32_t required_ids[] = {
    0x43495041, 0x4746434d, 0x54445447, 0x54524f49, 0x324d5054,
};

static void fixture_init(Fixture *f, bool region, bool secure_interrupts)
{
    memset(f, 0, sizeof(*f));
    virt_drtm_workflow_init(&f->workflow);
    f->parameters = (VirtDRTMParameters) {
        .launch_features = (region ? 1U << 3 : 0) |
                           (secure_interrupts ? 1U << 7 : 0),
        .memory_protection = region,
        .disable_secure_interrupts = secure_interrupts,
        .dlme_address = DLME_ADDRESS,
        .dlme_size = DLME_SIZE,
        .image_address = DLME_ADDRESS,
        .image_size = sizeof(f->image),
        .entry_address = DLME_ADDRESS + 0x100,
        .data_address = DATA_ADDRESS,
        .data_offset = DATA_ADDRESS - DLME_ADDRESS,
    };
    f->active_bank = VIRT_DRTM_TPM_ALG_SHA256;
    f->event = (VirtDRTMEventLogInput) {
        .active_banks = &f->active_bank,
        .active_bank_count = 1,
        .pcr_schema_value = 1,
        .secure_interrupts_disabled = secure_interrupts,
        .dlme_image = { f->image, sizeof(f->image) },
        .dlme_entry_point_offset = 0x100,
    };
    f->map = (VirtDRTMMemoryRegion) {
        DLME_ADDRESS, 0x08000000, VIRT_DRTM_MEMORY_NORMAL_CACHED, 3
    };
    f->protected = (VirtDRTMMemoryRegion) {
        DLME_ADDRESS, DLME_SIZE, VIRT_DRTM_MEMORY_NORMAL, 0
    };
    for (size_t i = 0; i < ARRAY_SIZE(f->hashes); i++) {
        f->hashes[i] = (VirtDRTMTCBHash) {
            .id = required_ids[i],
            .digest = f->digests[i],
            .digest_size = sizeof(f->digests[i]),
            .origin = VIRT_DRTM_TCB_HASH_IMPLEMENTATION,
        };
    }
    f->data = (VirtDRTMDataInput) {
        .dlme_address = DLME_ADDRESS,
        .dlme_size = DLME_SIZE,
        .image_address = DLME_ADDRESS,
        .image_size = sizeof(f->image),
        .complete_protection = !region,
        .protected_regions = region ? &f->protected : NULL,
        .protected_region_count = region ? 1 : 0,
        .address_map = &f->map,
        .address_map_count = 1,
        .firmware_hash_algorithm = VIRT_DRTM_TPM_ALG_SHA256,
        .tcb_hashes = f->hashes,
        .tcb_hash_count = ARRAY_SIZE(f->hashes),
    };
    f->preflight = (VirtDRTMPreflightInput) {
        .caller_aarch64 = true,
        .caller_is_boot_pe = true,
        .secondary_pes_off = true,
        .no_active_tpm_locality = true,
        .supported_launch_features = (1U << 3) | (1U << 7),
        .parameter_status = VIRT_DRTM_PARAM_SUCCESS,
        .parameters = &f->parameters,
        .event_log = &f->event,
        .data = &f->data,
    };
}

static VirtDRTMLaunchPlan *make_plan(Fixture *f)
{
    VirtDRTMLaunchPlan *plan = NULL;

    g_assert_cmpint(virt_drtm_workflow_preflight(&f->workflow,
                                                 &f->preflight, &plan),
                    ==, VIRT_DRTM_SUCCESS);
    g_assert_nonnull(plan);
    return plan;
}

static void enter_dlme(Fixture *f, VirtDRTMLaunchPlan *plan)
{
    g_assert_cmpint(virt_drtm_workflow_begin(&f->workflow, plan), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_open_localities(&f->workflow), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_enter_dce(&f->workflow), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_relinquish_locality(&f->workflow, 3),
                    ==, 0);
    g_assert_cmpint(virt_drtm_workflow_close_locality(&f->workflow, 3), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_activate_locality2(&f->workflow), ==,
                    0);
    g_assert_cmpint(virt_drtm_workflow_enter_dlme(&f->workflow), ==, 0);
}

static void test_preflight_plan(void)
{
    Fixture f;
    VirtDRTMLaunchPlan *plan;
    const VirtDRTMLaunchPlanInfo *info;
    VirtDRTMWorkflow before;

    fixture_init(&f, false, true);
    before = f.workflow;
    plan = make_plan(&f);
    info = virt_drtm_launch_plan_info(plan);
    g_assert_cmpmem(&f.workflow, sizeof(f.workflow), &before, sizeof(before));
    g_assert_cmphex(info->dlme_address, ==, DLME_ADDRESS);
    g_assert_cmphex(info->data_offset, ==, DATA_ADDRESS - DLME_ADDRESS);
    g_assert_cmphex(info->entry_address, ==, DLME_ADDRESS + 0x100);
    g_assert_cmpuint(info->event_log_size, >, 0);
    g_assert_cmpuint(info->dlme_data_size, >, info->event_log_size);
    g_assert_true(info->effects &
                  VIRT_DRTM_EFFECT_BUILD_SOFTWARE_MEASUREMENTS);
    g_assert_true(info->effects &
                  VIRT_DRTM_EFFECT_DISABLE_SECURE_INTERRUPTS);
    /* The committed transaction must not consult mutable source inputs. */
    f.parameters.memory_protection = 1;
    f.parameters.disable_secure_interrupts = false;
    f.data.complete_protection = false;
    g_assert_cmpint(virt_drtm_workflow_begin(&f.workflow, plan), ==, 0);
    g_assert_cmpint(f.workflow.protection, ==,
                    VIRT_DRTM_PROTECTION_COMPLETE);
    g_assert_cmpint(f.workflow.secure_interrupts, ==,
                    VIRT_DRTM_SECURE_INTERRUPTS_DISABLED);
    virt_drtm_launch_plan_free(plan);
}

static void assert_rejected_unchanged(Fixture *f, VirtDRTMResult expected)
{
    VirtDRTMWorkflow before = f->workflow;
    VirtDRTMLaunchPlan *plan = (void *)0x1;

    g_assert_cmpint(virt_drtm_workflow_preflight(&f->workflow, &f->preflight,
                                                 &plan), ==, expected);
    g_assert_null(plan);
    g_assert_cmpmem(&f->workflow, sizeof(f->workflow), &before,
                    sizeof(before));
}

static void test_preflight_priority_atomic(void)
{
    Fixture f;

    fixture_init(&f, false, false);
    f.workflow.phase = VIRT_DRTM_PHASE_DCRTM;
    f.preflight.caller_aarch64 = false;
    f.preflight.secondary_pes_off = false;
    assert_rejected_unchanged(&f, VIRT_DRTM_DENIED);

    fixture_init(&f, false, false);
    f.preflight.caller_aarch64 = false;
    f.preflight.secondary_pes_off = false;
    assert_rejected_unchanged(&f, VIRT_DRTM_DENIED);
    f.preflight.caller_aarch64 = true;
    f.preflight.secondary_pes_off = false;
    assert_rejected_unchanged(&f, VIRT_DRTM_SECONDARY_PE_NOT_OFF);
    f.preflight.secondary_pes_off = true;
    f.preflight.no_active_tpm_locality = false;
    f.preflight.parameter_status = VIRT_DRTM_MEM_PROTECT_INVALID;
    assert_rejected_unchanged(&f, VIRT_DRTM_DENIED);
    f.preflight.no_active_tpm_locality = true;
    assert_rejected_unchanged(&f,
                              VIRT_DRTM_WORKFLOW_MEM_PROTECT_INVALID);
    f.preflight.parameter_status = VIRT_DRTM_PARAM_SUCCESS;
    f.parameters.launch_features |= 1U << 6;
    assert_rejected_unchanged(&f,
                              VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    f.parameters.launch_features &= ~(1U << 6);
    f.event.dlme_entry_point_offset++;
    assert_rejected_unchanged(&f,
                              VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    f.event.dlme_entry_point_offset--;
    f.data.firmware_hash_algorithm = 0xc;
    assert_rejected_unchanged(&f,
                              VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    f.data.firmware_hash_algorithm = 0xb;
    f.parameters.pcr_schema = 1;
    assert_rejected_unchanged(&f,
                              VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    f.parameters.pcr_schema = 0;
    f.parameters.disable_secure_interrupts = true;
    assert_rejected_unchanged(&f,
                              VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    f.parameters.disable_secure_interrupts = false;
    f.event.pcr_schema_value = 2;
    assert_rejected_unchanged(&f,
                              VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
}

static void test_locality_lifecycle(void)
{
    Fixture f;
    VirtDRTMLaunchPlan *plan;

    fixture_init(&f, true, false);
    g_assert_cmpint(virt_drtm_workflow_close_locality(&f.workflow, 2), ==,
                    VIRT_DRTM_ALREADY_CLOSED);
    plan = make_plan(&f);
    g_assert_cmpint(virt_drtm_workflow_begin(&f.workflow, plan), ==, 0);
    g_assert_cmpint(f.workflow.locality[1], ==, VIRT_DRTM_LOCALITY_CLOSED);
    g_assert_cmpint(f.workflow.locality[2], ==, VIRT_DRTM_LOCALITY_CLOSED);
    g_assert_cmpint(f.workflow.locality[3], ==, VIRT_DRTM_LOCALITY_CLOSED);
    g_assert_cmpint(virt_drtm_workflow_enter_dce(&f.workflow), ==,
                    VIRT_DRTM_DENIED);
    f.workflow.locality[1] = VIRT_DRTM_LOCALITY_RELINQUISHED;
    g_assert_cmpint(virt_drtm_workflow_open_localities(&f.workflow), ==,
                    VIRT_DRTM_DENIED);
    f.workflow.locality[1] = VIRT_DRTM_LOCALITY_CLOSED;
    f.workflow.locality[2] = VIRT_DRTM_LOCALITY_OPEN;
    g_assert_cmpint(virt_drtm_workflow_open_localities(&f.workflow), ==,
                    VIRT_DRTM_DENIED);
    f.workflow.locality[2] = VIRT_DRTM_LOCALITY_CLOSED;
    f.workflow.locality[3] = VIRT_DRTM_LOCALITY_RELINQUISHED;
    g_assert_cmpint(virt_drtm_workflow_open_localities(&f.workflow), ==,
                    VIRT_DRTM_DENIED);
    f.workflow.locality[3] = VIRT_DRTM_LOCALITY_CLOSED;
    g_assert_cmpint(virt_drtm_workflow_open_localities(&f.workflow), ==, 0);
    g_assert_cmpint(f.workflow.locality[1], ==, VIRT_DRTM_LOCALITY_OPEN);
    g_assert_cmpint(f.workflow.locality[2], ==, VIRT_DRTM_LOCALITY_OPEN);
    g_assert_cmpint(f.workflow.locality[3], ==, VIRT_DRTM_LOCALITY_ACTIVE);
    g_assert_cmpint(virt_drtm_workflow_relinquish_locality(&f.workflow, 2),
                    ==, VIRT_DRTM_DENIED);
    g_assert_cmpint(virt_drtm_workflow_close_locality(&f.workflow, 3), ==,
                    VIRT_DRTM_DENIED);
    g_assert_cmpint(virt_drtm_workflow_close_locality(&f.workflow, 4), ==,
                    VIRT_DRTM_WORKFLOW_INVALID_PARAMETERS);
    g_assert_cmpint(virt_drtm_workflow_enter_dce(&f.workflow), ==, 0);
    g_assert_cmpint(f.workflow.locality[1], ==, VIRT_DRTM_LOCALITY_OPEN);
    g_assert_cmpint(virt_drtm_workflow_enter_dlme(&f.workflow), ==,
                    VIRT_DRTM_DENIED);
    g_assert_cmpint(virt_drtm_workflow_relinquish_locality(&f.workflow, 3),
                    ==, 0);
    g_assert_cmpint(virt_drtm_workflow_close_locality(&f.workflow, 3), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_close_locality(&f.workflow, 3), ==,
                    VIRT_DRTM_ALREADY_CLOSED);
    g_assert_cmpint(virt_drtm_workflow_activate_locality2(&f.workflow), ==,
                    0);
    g_assert_cmpint(virt_drtm_workflow_enter_dlme(&f.workflow), ==, 0);
    g_assert_cmpint(f.workflow.locality[2], ==, VIRT_DRTM_LOCALITY_ACTIVE);
    virt_drtm_launch_plan_free(plan);
}

static void test_release_semantics(void)
{
    Fixture f;
    VirtDRTMLaunchPlan *plan;

    fixture_init(&f, false, true);
    plan = make_plan(&f);
    enter_dlme(&f, plan);
    g_assert_cmpint(virt_drtm_workflow_unprotect(&f.workflow), ==, 0);
    g_assert_cmpint(f.workflow.protection, ==,
                    VIRT_DRTM_PROTECTION_COMPLETE_RETAINED);
    g_assert_cmpint(virt_drtm_workflow_unprotect(&f.workflow), ==,
                    VIRT_DRTM_DENIED);
    g_assert_cmpint(virt_drtm_workflow_enable_secure_interrupts(&f.workflow),
                    ==, 0);
    g_assert_cmpint(virt_drtm_workflow_enable_secure_interrupts(&f.workflow),
                    ==, VIRT_DRTM_DENIED);
    virt_drtm_launch_plan_free(plan);

    fixture_init(&f, true, false);
    plan = make_plan(&f);
    enter_dlme(&f, plan);
    g_assert_cmpint(virt_drtm_workflow_unprotect(&f.workflow), ==, 0);
    g_assert_cmpint(f.workflow.protection, ==, VIRT_DRTM_PROTECTION_NONE);
    g_assert_cmpint(virt_drtm_workflow_enable_secure_interrupts(&f.workflow),
                    ==, VIRT_DRTM_DENIED);
    virt_drtm_launch_plan_free(plan);
}

static void test_error_and_reset(void)
{
    Fixture f;
    VirtDRTMLaunchPlan *plan;
    uint64_t data = UINT64_C(0x12345) << 11;

    fixture_init(&f, false, false);
    f.workflow.sticky_error = 0xdead;
    plan = make_plan(&f);
    g_assert_cmpint(virt_drtm_workflow_set_error(&f.workflow, 1), ==,
                    VIRT_DRTM_DENIED);
    g_assert_cmpint(virt_drtm_workflow_begin(&f.workflow, plan), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_open_localities(&f.workflow), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_enter_dce(&f.workflow), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_set_error(&f.workflow,
                                                 data | (5 << 3) | 7), ==, 0);
    g_assert_cmphex(virt_drtm_workflow_get_error(&f.workflow), ==,
                    data | (5 << 3) | 4);
    g_assert_cmpint(virt_drtm_workflow_set_error(&f.workflow, 0), ==,
                    VIRT_DRTM_DENIED);
    virt_drtm_workflow_reset(&f.workflow);
    g_assert_cmphex(virt_drtm_workflow_get_error(&f.workflow), ==,
                    data | (5 << 3) | 4);
    virt_drtm_launch_plan_free(plan);

    fixture_init(&f, false, false);
    plan = make_plan(&f);
    enter_dlme(&f, plan);
    g_assert_cmphex(virt_drtm_workflow_get_error(&f.workflow), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_set_error(&f.workflow,
                                                 data | (2 << 3) | 1), ==, 0);
    g_assert_cmphex(virt_drtm_workflow_get_error(&f.workflow), ==,
                    data | (0xff << 3) | 5);
    virt_drtm_launch_plan_free(plan);
}

static void test_repeat_and_stale_plan(void)
{
    Fixture f;
    VirtDRTMLaunchPlan *first, *stale, *second;
    VirtDRTMWorkflow before;

    fixture_init(&f, false, false);
    first = make_plan(&f);
    stale = make_plan(&f);
    enter_dlme(&f, first);
    assert_rejected_unchanged(&f, VIRT_DRTM_DENIED);
    g_assert_cmpint(virt_drtm_workflow_unprotect(&f.workflow), ==, 0);
    assert_rejected_unchanged(&f, VIRT_DRTM_DENIED);
    g_assert_cmpint(virt_drtm_workflow_relinquish_locality(&f.workflow, 2),
                    ==, 0);
    second = make_plan(&f);
    before = f.workflow;
    g_assert_cmpint(virt_drtm_workflow_begin(&f.workflow, stale), ==,
                    VIRT_DRTM_DENIED);
    g_assert_cmpmem(&f.workflow, sizeof(f.workflow), &before, sizeof(before));
    g_assert_cmpint(virt_drtm_workflow_begin(&f.workflow, second), ==, 0);
    g_assert_cmpuint(f.workflow.launch_sequence, ==, 2);
    virt_drtm_launch_plan_free(first);
    virt_drtm_launch_plan_free(stale);
    virt_drtm_launch_plan_free(second);
}

static void test_observe_no_active_locality_is_narrow(void)
{
    VirtDRTMWorkflow workflow, before;

    virt_drtm_workflow_init(&workflow);
    workflow.phase = VIRT_DRTM_PHASE_DLME;
    workflow.locality[1] = VIRT_DRTM_LOCALITY_OPEN;
    workflow.locality[2] = VIRT_DRTM_LOCALITY_ACTIVE;
    workflow.locality[3] = VIRT_DRTM_LOCALITY_CLOSED;
    virt_drtm_workflow_observe_no_active_locality(&workflow);
    g_assert_cmpint(workflow.locality[2], ==,
                    VIRT_DRTM_LOCALITY_RELINQUISHED);

    workflow.locality[2] = VIRT_DRTM_LOCALITY_ACTIVE;
    workflow.phase = VIRT_DRTM_PHASE_DCE;
    before = workflow;
    virt_drtm_workflow_observe_no_active_locality(&workflow);
    g_assert_cmpmem(&workflow, sizeof(workflow), &before, sizeof(before));

    workflow.phase = VIRT_DRTM_PHASE_DLME;
    workflow.locality[3] = VIRT_DRTM_LOCALITY_ACTIVE;
    before = workflow;
    virt_drtm_workflow_observe_no_active_locality(&workflow);
    g_assert_cmpmem(&workflow, sizeof(workflow), &before, sizeof(before));
}

typedef struct LaunchMock {
    VirtDRTMLaunchStage fail;
    VirtDRTMLaunchStage break_workflow_after;
    unsigned int calls[VIRT_DRTM_LAUNCH_COMPLETE + 1];
    VirtDRTMLaunchStage order[VIRT_DRTM_LAUNCH_COMPLETE + 1];
    size_t order_count;
    unsigned int reset_count;
    bool probe_transport_error;
    VirtDRTMWorkflow *workflow;
    uint64_t write_address;
    size_t write_size;
} LaunchMock;

static void launch_record(LaunchMock *mock, VirtDRTMLaunchStage stage)
{
    mock->calls[stage]++;
    mock->order[mock->order_count++] = stage;
}

static bool launch_probe(void *opaque, bool *no_active, Error **errp)
{
    LaunchMock *mock = opaque;

    launch_record(mock, VIRT_DRTM_LAUNCH_PROBE);
    if (mock->probe_transport_error) {
        error_setg(errp, "injected probe transport failure");
        return false;
    }
    *no_active = mock->fail != VIRT_DRTM_LAUNCH_PROBE;
    return true;
}

static bool launch_open(void *opaque, Error **errp)
{
    LaunchMock *mock = opaque;

    launch_record(mock, VIRT_DRTM_LAUNCH_OPEN_LOCALITIES);
    if (mock->break_workflow_after == VIRT_DRTM_LAUNCH_OPEN_LOCALITIES) {
        mock->workflow->locality[2] = VIRT_DRTM_LOCALITY_OPEN;
    }
    return mock->fail != VIRT_DRTM_LAUNCH_OPEN_LOCALITIES;
}

static VirtDRTMTPMResult launch_hash_dce(
    void *opaque, const VirtDRTMMeasurementManifest *manifest, Error **errp)
{
    LaunchMock *mock = opaque;

    launch_record(mock, VIRT_DRTM_LAUNCH_HASH_DCE);
    g_assert_nonnull(manifest);
    return (VirtDRTMTPMResult) {
        .status = mock->fail == VIRT_DRTM_LAUNCH_HASH_DCE ?
            VIRT_DRTM_TPM_HASH_ERROR : VIRT_DRTM_TPM_OK,
        .irreversible = true,
    };
}

static VirtDRTMTPMResult launch_extend_dcrtm(
    void *opaque, const VirtDRTMMeasurementManifest *manifest, Error **errp)
{
    LaunchMock *mock = opaque;

    launch_record(mock, VIRT_DRTM_LAUNCH_EXTEND_DCRTM);
    g_assert_nonnull(manifest);
    if (mock->break_workflow_after == VIRT_DRTM_LAUNCH_EXTEND_DCRTM) {
        mock->workflow->locality[1] = VIRT_DRTM_LOCALITY_CLOSED;
    }
    return (VirtDRTMTPMResult) {
        .status = mock->fail == VIRT_DRTM_LAUNCH_EXTEND_DCRTM ?
            VIRT_DRTM_TPM_TRANSPORT_ERROR : VIRT_DRTM_TPM_OK,
        .irreversible = true,
    };
}

static VirtDRTMTPMResult launch_extend_dce(
    void *opaque, const VirtDRTMMeasurementManifest *manifest, Error **errp)
{
    LaunchMock *mock = opaque;

    launch_record(mock, VIRT_DRTM_LAUNCH_EXTEND_DCE);
    g_assert_nonnull(manifest);
    g_assert_cmpint(mock->workflow->phase, ==, VIRT_DRTM_PHASE_DCE);
    return (VirtDRTMTPMResult) {
        .status = mock->fail == VIRT_DRTM_LAUNCH_EXTEND_DCE ?
            VIRT_DRTM_TPM_TRANSPORT_ERROR : VIRT_DRTM_TPM_OK,
        .irreversible = true,
    };
}

static bool launch_write(void *opaque, uint64_t address, const uint8_t *data,
                         size_t size, Error **errp)
{
    LaunchMock *mock = opaque;

    launch_record(mock, VIRT_DRTM_LAUNCH_WRITE_DATA);
    mock->write_address = address;
    mock->write_size = size;
    g_assert_nonnull(data);
    return mock->fail != VIRT_DRTM_LAUNCH_WRITE_DATA;
}

static bool launch_close(void *opaque, TPMDRTMLocalityCloseResult *result,
                         Error **errp)
{
    LaunchMock *mock = opaque;

    launch_record(mock, VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3);
    *result = TPM_DRTM_LOCALITY_CLOSED;
    if (mock->break_workflow_after == VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3) {
        mock->workflow->locality[3] = VIRT_DRTM_LOCALITY_CLOSED;
    }
    return mock->fail != VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3;
}

static bool launch_activate(void *opaque, Error **errp)
{
    LaunchMock *mock = opaque;

    launch_record(mock, VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2);
    if (mock->break_workflow_after == VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2) {
        mock->workflow->locality[3] = VIRT_DRTM_LOCALITY_OPEN;
    }
    return mock->fail != VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2;
}

static bool launch_enter(void *opaque, uint64_t dlme, uint64_t data_offset,
                         uint64_t entry, Error **errp)
{
    LaunchMock *mock = opaque;

    launch_record(mock, VIRT_DRTM_LAUNCH_CPU_ENTRY);
    g_assert_cmphex(dlme, ==, DLME_ADDRESS);
    g_assert_cmphex(data_offset, ==, DATA_ADDRESS - DLME_ADDRESS);
    g_assert_cmphex(entry, ==, DLME_ADDRESS + 0x100);
    g_assert_cmpint(mock->workflow->phase, ==, VIRT_DRTM_PHASE_DCE);
    g_assert_cmpint(mock->workflow->locality[2], ==,
                    VIRT_DRTM_LOCALITY_ACTIVE);
    g_assert_cmphex(mock->workflow->sticky_error, ==, 0);
    return mock->fail != VIRT_DRTM_LAUNCH_CPU_ENTRY;
}

static void launch_reset(void *opaque)
{
    LaunchMock *mock = opaque;

    g_assert_cmpint(mock->workflow->phase, ==, VIRT_DRTM_PHASE_REMEDIATION);
    g_assert_cmphex(mock->workflow->sticky_error, !=, 0);
    mock->reset_count++;
}

static const VirtDRTMLaunchOps launch_ops = {
    .no_active_locality = launch_probe,
    .open_localities = launch_open,
    .hash_dce = launch_hash_dce,
    .extend_dcrtm = launch_extend_dcrtm,
    .extend_dce = launch_extend_dce,
    .write = launch_write,
    .close_locality3 = launch_close,
    .activate_locality2 = launch_activate,
    .enter_dlme = launch_enter,
    .request_cold_reset = launch_reset,
};

static void test_launch_success(void)
{
    static const VirtDRTMLaunchStage expected_order[] = {
        VIRT_DRTM_LAUNCH_PROBE,
        VIRT_DRTM_LAUNCH_OPEN_LOCALITIES,
        VIRT_DRTM_LAUNCH_HASH_DCE,
        VIRT_DRTM_LAUNCH_EXTEND_DCRTM,
        VIRT_DRTM_LAUNCH_EXTEND_DCE,
        VIRT_DRTM_LAUNCH_WRITE_DATA,
        VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3,
        VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2,
        VIRT_DRTM_LAUNCH_CPU_ENTRY,
    };
    Fixture f;
    LaunchMock mock = {
        .fail = VIRT_DRTM_LAUNCH_COMPLETE,
        .workflow = &f.workflow,
    };
    VirtDRTMLaunchPlan *plan;
    VirtDRTMLaunchResult result;

    fixture_init(&f, false, false);
    plan = make_plan(&f);
    result = virt_drtm_launch_execute(&f.workflow, plan, true, &launch_ops,
                                      &mock, NULL);
    g_assert_cmpint(result.result, ==, VIRT_DRTM_SUCCESS);
    g_assert_true(result.committed);
    g_assert_false(result.reset_requested);
    g_assert_true(result.non_returning);
    g_assert_cmpuint(mock.reset_count, ==, 0);
    g_assert_cmpint(result.stage, ==, VIRT_DRTM_LAUNCH_COMPLETE);
    g_assert_cmpint(f.workflow.phase, ==, VIRT_DRTM_PHASE_DLME);
    g_assert_cmpint(f.workflow.locality[3], ==, VIRT_DRTM_LOCALITY_CLOSED);
    g_assert_cmpint(f.workflow.locality[2], ==, VIRT_DRTM_LOCALITY_ACTIVE);
    g_assert_cmphex(f.workflow.sticky_error, ==, 0);
    g_assert_cmphex(mock.write_address, ==, DATA_ADDRESS);
    g_assert_cmpuint(mock.write_size, >, 0);
    g_assert_cmpuint(mock.order_count, ==, ARRAY_SIZE(expected_order));
    g_assert_cmpmem(mock.order, sizeof(expected_order), expected_order,
                    sizeof(expected_order));
    virt_drtm_launch_plan_free(plan);
}

static void test_launch_repeat_without_reset(void)
{
    static const VirtDRTMLaunchStage expected_order[] = {
        VIRT_DRTM_LAUNCH_PROBE,
        VIRT_DRTM_LAUNCH_OPEN_LOCALITIES,
        VIRT_DRTM_LAUNCH_HASH_DCE,
        VIRT_DRTM_LAUNCH_EXTEND_DCRTM,
        VIRT_DRTM_LAUNCH_EXTEND_DCE,
        VIRT_DRTM_LAUNCH_WRITE_DATA,
        VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3,
        VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2,
        VIRT_DRTM_LAUNCH_CPU_ENTRY,
    };
    Fixture f;
    LaunchMock mock = {
        .fail = VIRT_DRTM_LAUNCH_COMPLETE,
        .workflow = &f.workflow,
    };
    VirtDRTMLaunchPlan *first, *second, *third;
    VirtDRTMLaunchResult result;

    fixture_init(&f, true, true);
    first = make_plan(&f);
    result = virt_drtm_launch_execute(&f.workflow, first, true, &launch_ops,
                                      &mock, NULL);
    g_assert_cmpint(result.result, ==, VIRT_DRTM_SUCCESS);
    g_assert_cmpint(f.workflow.locality[1], ==, VIRT_DRTM_LOCALITY_OPEN);

    g_assert_cmpint(virt_drtm_workflow_unprotect(&f.workflow), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_relinquish_locality(&f.workflow, 2),
                    ==, 0);
    assert_rejected_unchanged(&f, VIRT_DRTM_DENIED);
    g_assert_cmpint(virt_drtm_workflow_enable_secure_interrupts(&f.workflow),
                    ==, 0);
    second = make_plan(&f);

    mock.order_count = 0;
    result = virt_drtm_launch_execute(&f.workflow, second, true, &launch_ops,
                                      &mock, NULL);
    g_assert_cmpint(result.result, ==, VIRT_DRTM_SUCCESS);
    g_assert_cmpint(result.stage, ==, VIRT_DRTM_LAUNCH_COMPLETE);
    g_assert_true(result.committed);
    g_assert_true(result.non_returning);
    g_assert_false(result.reset_requested);
    g_assert_cmpuint(mock.reset_count, ==, 0);
    g_assert_cmpuint(mock.order_count, ==, ARRAY_SIZE(expected_order));
    g_assert_cmpmem(mock.order, sizeof(expected_order), expected_order,
                    sizeof(expected_order));
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_PROBE], ==, 2);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_OPEN_LOCALITIES], ==, 2);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_HASH_DCE], ==, 2);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_EXTEND_DCRTM], ==, 2);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_EXTEND_DCE], ==, 2);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_CPU_ENTRY], ==, 2);
    g_assert_cmpuint(f.workflow.launch_sequence, ==, 2);
    g_assert_cmpint(f.workflow.phase, ==, VIRT_DRTM_PHASE_DLME);
    g_assert_cmpint(f.workflow.locality[1], ==, VIRT_DRTM_LOCALITY_OPEN);
    g_assert_cmpint(f.workflow.locality[2], ==, VIRT_DRTM_LOCALITY_ACTIVE);
    g_assert_cmpint(f.workflow.locality[3], ==, VIRT_DRTM_LOCALITY_CLOSED);

    g_assert_cmpint(virt_drtm_workflow_unprotect(&f.workflow), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_relinquish_locality(&f.workflow, 2),
                    ==, 0);
    g_assert_cmpint(virt_drtm_workflow_close_locality(&f.workflow, 2), ==, 0);
    g_assert_cmpint(virt_drtm_workflow_enable_secure_interrupts(&f.workflow),
                    ==, 0);
    third = make_plan(&f);

    mock.order_count = 0;
    result = virt_drtm_launch_execute(&f.workflow, third, true, &launch_ops,
                                      &mock, NULL);
    g_assert_cmpint(result.result, ==, VIRT_DRTM_SUCCESS);
    g_assert_cmpint(result.stage, ==, VIRT_DRTM_LAUNCH_COMPLETE);
    g_assert_true(result.committed);
    g_assert_true(result.non_returning);
    g_assert_false(result.reset_requested);
    g_assert_cmpuint(mock.reset_count, ==, 0);
    g_assert_cmpuint(mock.order_count, ==, ARRAY_SIZE(expected_order));
    g_assert_cmpmem(mock.order, sizeof(expected_order), expected_order,
                    sizeof(expected_order));
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_PROBE], ==, 3);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_OPEN_LOCALITIES], ==, 3);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_HASH_DCE], ==, 3);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_EXTEND_DCRTM], ==, 3);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_EXTEND_DCE], ==, 3);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_WRITE_DATA], ==, 3);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3], ==, 3);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2], ==, 3);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_CPU_ENTRY], ==, 3);
    g_assert_cmpuint(f.workflow.launch_sequence, ==, 3);
    g_assert_cmpint(f.workflow.phase, ==, VIRT_DRTM_PHASE_DLME);
    g_assert_cmpint(f.workflow.locality[1], ==, VIRT_DRTM_LOCALITY_OPEN);
    g_assert_cmpint(f.workflow.locality[2], ==, VIRT_DRTM_LOCALITY_ACTIVE);
    g_assert_cmpint(f.workflow.locality[3], ==, VIRT_DRTM_LOCALITY_CLOSED);
    virt_drtm_launch_plan_free(first);
    virt_drtm_launch_plan_free(second);
    virt_drtm_launch_plan_free(third);
}

static void test_launch_probe_transport_failure(void)
{
    Fixture f;
    LaunchMock mock = {
        .fail = VIRT_DRTM_LAUNCH_COMPLETE,
        .probe_transport_error = true,
        .workflow = &f.workflow,
    };
    VirtDRTMWorkflow before;
    VirtDRTMLaunchPlan *plan;
    VirtDRTMLaunchResult result;
    Error *err = NULL;

    fixture_init(&f, false, false);
    plan = make_plan(&f);
    before = f.workflow;
    result = virt_drtm_launch_execute(&f.workflow, plan, true, &launch_ops,
                                      &mock, &err);
    g_assert_cmpint(result.result, ==, VIRT_DRTM_TPM_ERROR);
    g_assert_cmpint(result.stage, ==, VIRT_DRTM_LAUNCH_PROBE);
    g_assert_false(result.committed);
    g_assert_false(result.reset_requested);
    g_assert_false(result.non_returning);
    g_assert_cmpuint(mock.reset_count, ==, 0);
    g_assert_cmpmem(&f.workflow, sizeof(f.workflow), &before, sizeof(before));
    g_assert_nonnull(err);
    error_free(err);
    virt_drtm_launch_plan_free(plan);
}

static void test_launch_failure_boundaries(void)
{
    static const VirtDRTMLaunchStage failures[] = {
        VIRT_DRTM_LAUNCH_PROBE,
        VIRT_DRTM_LAUNCH_OPEN_LOCALITIES,
        VIRT_DRTM_LAUNCH_HASH_DCE,
        VIRT_DRTM_LAUNCH_EXTEND_DCRTM,
        VIRT_DRTM_LAUNCH_EXTEND_DCE,
        VIRT_DRTM_LAUNCH_WRITE_DATA,
        VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3,
        VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2,
        VIRT_DRTM_LAUNCH_CPU_ENTRY,
    };

    for (size_t i = 0; i < ARRAY_SIZE(failures); i++) {
        Fixture f;
        LaunchMock mock = { .fail = failures[i], .workflow = &f.workflow };
        VirtDRTMWorkflow before;
        VirtDRTMLaunchPlan *plan;
        VirtDRTMLaunchResult result;

        fixture_init(&f, false, false);
        plan = make_plan(&f);
        before = f.workflow;
        result = virt_drtm_launch_execute(&f.workflow, plan, true,
                                          &launch_ops, &mock, NULL);
        g_assert_cmpint(result.stage, ==, failures[i]);
        if (failures[i] == VIRT_DRTM_LAUNCH_PROBE) {
            g_assert_false(result.committed);
            g_assert_false(result.reset_requested);
            g_assert_false(result.non_returning);
            g_assert_cmpuint(mock.reset_count, ==, 0);
            g_assert_cmpint(result.result, ==, VIRT_DRTM_DENIED);
            g_assert_cmpmem(&f.workflow, sizeof(f.workflow), &before,
                            sizeof(before));
        } else {
            uint8_t error_id;
            uint8_t error_phase;

            g_assert_true(result.committed);
            g_assert_true(result.reset_requested);
            g_assert_true(result.non_returning);
            g_assert_cmpuint(mock.reset_count, ==, 1);
            g_assert_cmpint(f.workflow.phase, ==,
                            VIRT_DRTM_PHASE_REMEDIATION);
            error_phase =
                failures[i] <= VIRT_DRTM_LAUNCH_EXTEND_DCRTM ? 1 : 3;
            switch (failures[i]) {
            case VIRT_DRTM_LAUNCH_OPEN_LOCALITIES:
            case VIRT_DRTM_LAUNCH_HASH_DCE:
            case VIRT_DRTM_LAUNCH_EXTEND_DCRTM:
            case VIRT_DRTM_LAUNCH_EXTEND_DCE:
            case VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3:
            case VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2:
                /* DEN0113 Table 8: every TPM error uses error ID 0x5. */
                error_id = 0x05;
                break;
            default:
                /* These injected failures are implementation-defined. */
                error_id = 0xff;
                break;
            }
            g_assert_cmphex(f.workflow.sticky_error, ==,
                            ((uint64_t)error_id << 3) | error_phase);
        }
        virt_drtm_launch_plan_free(plan);
    }
}

static void test_launch_separator_failure_is_dce_error(void)
{
    Fixture f;
    LaunchMock mock = {
        .fail = VIRT_DRTM_LAUNCH_EXTEND_DCE,
        .workflow = &f.workflow,
    };
    const VirtDRTMMeasurementManifest *manifest;
    const VirtDRTMMeasurementOperation *operation;
    const VirtDRTMMeasurementEvent *event = NULL;
    VirtDRTMLaunchPlan *plan;
    VirtDRTMLaunchResult result;
    size_t boundary;

    fixture_init(&f, false, false);
    plan = make_plan(&f);
    manifest = virt_drtm_launch_plan_manifest(plan);
    boundary = virt_drtm_measurement_manifest_dce_operation(manifest);
    operation = virt_drtm_measurement_manifest_operation(manifest, boundary);
    for (size_t i = 0;
         i < virt_drtm_measurement_manifest_event_count(manifest); i++) {
        const VirtDRTMMeasurementEvent *candidate =
            virt_drtm_measurement_manifest_event(manifest, i);

        if (candidate->pcr == 17 &&
            candidate->type == VIRT_DRTM_EV_SEPARATOR) {
            event = candidate;
            break;
        }
    }
    g_assert_nonnull(event);
    g_assert_cmpint(operation->type, ==, VIRT_DRTM_MEASUREMENT_PCR_EXTEND);
    g_assert_cmpuint(operation->pcr, ==, event->pcr);
    g_assert_cmpmem(operation->digest.value, operation->digest.size,
                    event->digests[0].value, event->digests[0].size);

    /* The first DCE-owned extend fails after enter_dce(). */
    result = virt_drtm_launch_execute(&f.workflow, plan, true, &launch_ops,
                                      &mock, NULL);
    g_assert_cmpint(result.stage, ==, VIRT_DRTM_LAUNCH_EXTEND_DCE);
    g_assert_true(result.committed);
    g_assert_true(result.reset_requested);
    g_assert_true(result.non_returning);
    g_assert_cmpint(f.workflow.phase, ==, VIRT_DRTM_PHASE_REMEDIATION);
    g_assert_cmphex(f.workflow.sticky_error, ==, (UINT64_C(0x05) << 3) | 3);
    g_assert_cmpuint(mock.reset_count, ==, 1);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_EXTEND_DCRTM], ==, 1);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_EXTEND_DCE], ==, 1);

    virt_drtm_workflow_reset(&f.workflow);
    g_assert_cmpint(f.workflow.phase, ==, VIRT_DRTM_PHASE_READY);
    g_assert_cmphex(f.workflow.sticky_error, ==, (UINT64_C(0x05) << 3) | 3);
    virt_drtm_launch_plan_free(plan);
}

static void test_launch_pcr18_prefix_failure_is_dcrtm_error(void)
{
    Fixture f;
    LaunchMock mock = {
        .fail = VIRT_DRTM_LAUNCH_EXTEND_DCRTM,
        .workflow = &f.workflow,
    };
    const VirtDRTMMeasurementManifest *manifest;
    const VirtDRTMMeasurementOperation *operation;
    VirtDRTMLaunchPlan *plan;
    VirtDRTMLaunchResult result;
    size_t boundary;

    fixture_init(&f, false, false);
    plan = make_plan(&f);
    manifest = virt_drtm_launch_plan_manifest(plan);
    boundary = virt_drtm_measurement_manifest_dce_operation(manifest);
    operation = virt_drtm_measurement_manifest_operation(manifest,
                                                          boundary - 1);
    g_assert_cmpint(operation->type, ==, VIRT_DRTM_MEASUREMENT_PCR_EXTEND);
    g_assert_cmpuint(operation->pcr, ==, 18);

    result = virt_drtm_launch_execute(&f.workflow, plan, true, &launch_ops,
                                      &mock, NULL);
    g_assert_cmpint(result.stage, ==, VIRT_DRTM_LAUNCH_EXTEND_DCRTM);
    g_assert_true(result.committed);
    g_assert_true(result.reset_requested);
    g_assert_cmpint(f.workflow.phase, ==, VIRT_DRTM_PHASE_REMEDIATION);
    g_assert_cmphex(f.workflow.sticky_error, ==, (UINT64_C(0x05) << 3) | 1);
    g_assert_cmpuint(mock.reset_count, ==, 1);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_EXTEND_DCRTM], ==, 1);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_EXTEND_DCE], ==, 0);
    virt_drtm_launch_plan_free(plan);
}

static void test_launch_internal_transition_failures(void)
{
    static const struct {
        VirtDRTMLaunchStage stage;
        uint8_t phase;
    } failures[] = {
        { VIRT_DRTM_LAUNCH_OPEN_LOCALITIES, 1 },
        { VIRT_DRTM_LAUNCH_EXTEND_DCRTM, 1 },
        { VIRT_DRTM_LAUNCH_CLOSE_LOCALITY3, 3 },
        { VIRT_DRTM_LAUNCH_ACTIVATE_LOCALITY2, 3 },
    };

    for (size_t i = 0; i < ARRAY_SIZE(failures); i++) {
        Fixture f;
        LaunchMock mock = {
            .fail = VIRT_DRTM_LAUNCH_COMPLETE,
            .break_workflow_after = failures[i].stage,
            .workflow = &f.workflow,
        };
        VirtDRTMLaunchPlan *plan;
        VirtDRTMLaunchResult result;

        fixture_init(&f, false, false);
        plan = make_plan(&f);
        result = virt_drtm_launch_execute(&f.workflow, plan, true,
                                          &launch_ops, &mock, NULL);
        g_assert_cmpint(result.stage, ==, failures[i].stage);
        g_assert_true(result.committed);
        g_assert_true(result.reset_requested);
        g_assert_true(result.non_returning);
        g_assert_cmpuint(mock.reset_count, ==, 1);
        g_assert_cmpint(f.workflow.phase, ==, VIRT_DRTM_PHASE_REMEDIATION);
        g_assert_cmphex(f.workflow.sticky_error, ==,
                        (UINT64_C(0xff) << 3) | failures[i].phase);
        virt_drtm_launch_plan_free(plan);
    }
}

static void test_launch_unlocked_tcb_remediation(void)
{
    Fixture f;
    LaunchMock mock = {
        .fail = VIRT_DRTM_LAUNCH_COMPLETE,
        .workflow = &f.workflow,
    };
    VirtDRTMLaunchPlan *plan;
    VirtDRTMLaunchResult result;

    fixture_init(&f, false, false);
    plan = make_plan(&f);
    result = virt_drtm_launch_execute(&f.workflow, plan, false, &launch_ops,
                                      &mock, NULL);
    g_assert_true(result.committed);
    g_assert_cmpint(result.stage, ==, VIRT_DRTM_LAUNCH_TCB_LOCK);
    g_assert_cmpint(f.workflow.phase, ==, VIRT_DRTM_PHASE_REMEDIATION);
    g_assert_cmphex(f.workflow.sticky_error, ==, (0x04 << 3) | 3);
    g_assert_true(result.reset_requested);
    g_assert_true(result.non_returning);
    g_assert_cmpuint(mock.reset_count, ==, 1);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_HASH_DCE], ==, 1);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_EXTEND_DCRTM], ==, 1);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_EXTEND_DCE], ==, 1);
    g_assert_cmpuint(mock.calls[VIRT_DRTM_LAUNCH_WRITE_DATA], ==, 0);
    virt_drtm_launch_plan_free(plan);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/arm/drtm-workflow/preflight-plan", test_preflight_plan);
    g_test_add_func("/arm/drtm-workflow/preflight-priority-atomic",
                    test_preflight_priority_atomic);
    g_test_add_func("/arm/drtm-workflow/observe-no-active-narrow",
                    test_observe_no_active_locality_is_narrow);
    g_test_add_func("/arm/drtm-workflow/locality-lifecycle",
                    test_locality_lifecycle);
    g_test_add_func("/arm/drtm-workflow/release-semantics",
                    test_release_semantics);
    g_test_add_func("/arm/drtm-workflow/error-reset", test_error_and_reset);
    g_test_add_func("/arm/drtm-workflow/repeat-stale",
                    test_repeat_and_stale_plan);
    g_test_add_func("/arm/drtm-workflow/launch-success", test_launch_success);
    g_test_add_func("/arm/drtm-workflow/launch-repeat-without-reset",
                    test_launch_repeat_without_reset);
    g_test_add_func("/arm/drtm-workflow/launch-failure-boundaries",
                    test_launch_failure_boundaries);
    g_test_add_func("/arm/drtm-workflow/launch-separator-failure",
                    test_launch_separator_failure_is_dce_error);
    g_test_add_func("/arm/drtm-workflow/launch-pcr18-prefix-failure",
                    test_launch_pcr18_prefix_failure_is_dcrtm_error);
    g_test_add_func("/arm/drtm-workflow/launch-internal-transition-failures",
                    test_launch_internal_transition_failures);
    g_test_add_func("/arm/drtm-workflow/launch-probe-transport-failure",
                    test_launch_probe_transport_failure);
    g_test_add_func("/arm/drtm-workflow/launch-unlocked-tcb",
                    test_launch_unlocked_tcb_remediation);
    return g_test_run();
}
