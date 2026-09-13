/*
 * Arm virt DRTM firmware service
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/bitops.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "hw/arm/virt-drtm.h"
#include "system/tpm.h"
#include "migration/blocker.h"
#include "hw/core/qdev.h"
#include "system/reset.h"
#include "target/arm/cpu.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/runstate.h"
#include "virt-drtm-smc-internal.h"
#include "virt-drtm-features-internal.h"
#include "trace.h"

typedef struct VirtDRTMSMCContext {
    VirtDRTMState *service;
    ARMCPU *cpu;
} VirtDRTMSMCContext;

static const ARMFirmwareSMCRoute virt_drtm_route = {
    .conduit = ARM_FIRMWARE_SMCCC_CONDUIT_SMC,
    .function_base = DRTM_FID_BASE,
    .function_mask = BIT_ULL(DRTM_VERSION - DRTM_FID_BASE) |
                     BIT_ULL(DRTM_FEATURES - DRTM_FID_BASE) |
                     BIT_ULL(DRTM_UNPROTECT_MEMORY - DRTM_FID_BASE) |
                     BIT_ULL(DRTM_DYNAMIC_LAUNCH - DRTM_FID_BASE) |
                     BIT_ULL(DRTM_CLOSE_LOCALITY - DRTM_FID_BASE) |
                     BIT_ULL(DRTM_GET_ERROR - DRTM_FID_BASE) |
                     BIT_ULL(DRTM_SET_ERROR - DRTM_FID_BASE) |
                     BIT_ULL(DRTM_SET_TCB_HASH - DRTM_FID_BASE) |
                     BIT_ULL(DRTM_LOCK_TCB_HASHES - DRTM_FID_BASE) |
                     BIT_ULL(DRTM_ENABLE_SECURE_INTERRUPTS - DRTM_FID_BASE),
};

static bool virt_drtm_smc_read_guest(void *opaque, uint64_t address,
                                     void *data, size_t size)
{
    return address_space_read(&address_space_memory, address,
                              MEMTXATTRS_UNSPECIFIED, data, size) == MEMTX_OK;
}

static bool virt_drtm_smc_guest_is_ram(void *opaque, uint64_t address,
                                       uint64_t size)
{
    RCU_READ_LOCK_GUARD();

    while (size) {
        hwaddr translated, length = size;
        MemoryRegion *mr = address_space_translate(&address_space_memory,
            address, &translated, &length, false, MEMTXATTRS_UNSPECIFIED);

        if (!mr || !length || !memory_region_is_ram(mr) ||
            memory_region_is_rom(mr) || memory_region_is_ram_device(mr)) {
            return false;
        }
        address += length;
        size -= length;
    }
    return true;
}

static bool virt_drtm_smc_close_locality(
    void *opaque, uint8_t locality, TPMDRTMLocalityCloseResult *result,
    Error **errp)
{
#ifdef CONFIG_TPM
    VirtDRTMState *s = ((VirtDRTMSMCContext *)opaque)->service;

    return tpm_drtm_close_locality(s->tpm, locality, result, errp);
#else
    error_setg(errp, "virt DRTM TPM support is unavailable");
    return false;
#endif
}

static void virt_drtm_smc_request_cold_reset(void *opaque)
{
    qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
}

static VirtDRTMFeaturesResult virt_drtm_smc_features(void *opaque,
                                                      uint64_t query)
{
    VirtDRTMSMCContext *context = opaque;

    return virt_drtm_features_query(
        context->service, arm_cpu_mp_affinity(ARM_CPU(first_cpu)),
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, query);
}

static bool virt_drtm_smc_ensure_ready(void *opaque, Error **errp)
{
#ifdef CONFIG_TPM
    VirtDRTMState *s = ((VirtDRTMSMCContext *)opaque)->service;
    VirtDRTMTCBStore tcb_hashes;
    VirtDRTMTPMBanks banks;

    if (s->tpm_ready) {
        return true;
    }
    banks = virt_drtm_tpm_discover_banks_frontend(s->tpm, errp);
    if (banks.status != VIRT_DRTM_TPM_BANKS_OK) {
        return false;
    }
    if (!virt_drtm_tcb_init(&tcb_hashes, banks.selected_algorithm,
                            VIRT_DRTM_TCB_HASH_CAPACITY)) {
        error_setg(errp, "virt DRTM selected an unsupported firmware hash "
                   "algorithm 0x%04x", banks.selected_algorithm);
        return false;
    }

    s->tcb_hashes = tcb_hashes;
    memset(s->active_banks, 0, sizeof(s->active_banks));
    memcpy(s->active_banks, banks.banks,
           banks.bank_count * sizeof(banks.banks[0]));
    s->active_bank_count = banks.bank_count;
    s->firmware_hash_algorithm = banks.selected_algorithm;
    s->tpm_ready = true;
    return true;
#else
    error_setg(errp, "virt DRTM TPM support is unavailable");
    return false;
#endif
}

static VirtDRTMLaunchResult virt_drtm_smc_dynamic_launch(
    void *opaque, uint64_t parameters_address, Error **errp)
{
    VirtDRTMSMCContext *context = opaque;

    return virt_drtm_service_launch(context->service, context->cpu,
                                    parameters_address, errp);
}

static const VirtDRTMSMCOps virt_drtm_smc_ops = {
    .ensure_ready = virt_drtm_smc_ensure_ready,
    .guest_is_ram = virt_drtm_smc_guest_is_ram,
    .read_guest = virt_drtm_smc_read_guest,
    .close_locality = virt_drtm_smc_close_locality,
    .request_cold_reset = virt_drtm_smc_request_cold_reset,
    .features = virt_drtm_smc_features,
    .dynamic_launch = virt_drtm_smc_dynamic_launch,
};

static void virt_drtm_smc(ARMCPU *cpu, void *opaque)
{
    VirtDRTMState *s = opaque;
    VirtDRTMSMCContext context = { .service = s, .cpu = cpu };
    CPUARMState *env = &cpu->env;
    VirtDRTMSMCResult result;
    Error *local_err = NULL;
    uint32_t function;

    g_assert(bql_locked());
    g_assert(s->enabled);

    function = is_a64(env) ? env->xregs[0] : env->regs[0];
    result = virt_drtm_smc_dispatch_with_ops(s, is_a64(env), function,
                                             is_a64(env) ? env->xregs[1] : 0,
                                             &virt_drtm_smc_ops, &context,
                                             &local_err);
    trace_virt_drtm_workflow_call(cpu->parent_obj.cpu_index, function,
                                  result.status == VIRT_DRTM_NOT_SUPPORTED ?
                                  "dormant" : "handled");
    if (local_err) {
        error_reportf_err(local_err, "virt DRTM SMC 0x%08x failed: ",
                          function);
    }
    if (result.non_returning) {
        return;
    }
    if (!is_a64(env)) {
        env->regs[0] = (uint32_t)result.status;
        return;
    }
    env->xregs[0] = (uint64_t)(int64_t)result.status;
    if (result.has_x1) {
        env->xregs[1] = result.x1;
    }
}

bool virt_drtm_register_routes(VirtDRTMState *s, Error **errp)
{
    CPUState *cs;
    GPtrArray *registered;

    g_assert(!s->routes_registered);
    g_assert(!s->enabled);

    error_setg(&s->migration_blocker,
               "migration is not supported with virt DRTM workflow emulation");
    if (migrate_add_blocker(&s->migration_blocker, errp) < 0) {
        return false;
    }

    registered = g_ptr_array_new();
    CPU_FOREACH(cs) {
        if (!arm_cpu_register_firmware_smc_provider(ARM_CPU(cs),
                                                    &virt_drtm_route,
                                                    virt_drtm_smc, s, errp)) {
            for (unsigned int i = 0; i < registered->len; i++) {
                bool removed = arm_cpu_unregister_firmware_smc_provider(
                    ARM_CPU(g_ptr_array_index(registered, i)),
                    &virt_drtm_route, virt_drtm_smc, s);

                g_assert(removed);
            }
            g_ptr_array_free(registered, true);
            migrate_del_blocker(&s->migration_blocker);
            return false;
        }
        g_ptr_array_add(registered, cs);
    }

    g_ptr_array_free(registered, true);

    s->routes_registered = true;
    return true;
}

bool virt_drtm_start(VirtDRTMState *s, Error **errp)
{
#ifdef CONFIG_TPM
    TPMIf *tpm;
#else
    error_setg(errp, "virt DRTM requires TPM support in this QEMU build");
    return false;
#endif

    g_assert(s->routes_registered);
    g_assert(!s->enabled);

#ifdef CONFIG_TPM
    /* Bind the frontend before publishing the immutable service interface. */
    tpm = tpm_find();
    if (!tpm) {
        error_setg(errp, "virt DRTM requires exactly one TPM device");
        return false;
    }
    if (!object_dynamic_cast(OBJECT(tpm), TYPE_TPM_TIS_SYSBUS)) {
        error_setg(errp, "virt DRTM requires a tpm-tis-device frontend");
        return false;
    }
    if (tpm_get_version(tpm) != TPM_VERSION_2_0) {
        error_setg(errp, "virt DRTM requires a TPM 2.0 backend");
        return false;
    }
    s->tpm = tpm;
#endif

    s->enabled = true;
    qemu_register_resettable(OBJECT(s));
    s->reset_registered = true;
    trace_virt_drtm_workflow_enabled();
    return true;
}

static ResettableState *virt_drtm_get_reset_state(Object *obj)
{
    return &VIRT_DRTM(obj)->reset_state;
}

static void virt_drtm_reset_enter(Object *obj, ResetType type)
{
    VirtDRTMState *s = VIRT_DRTM(obj);

    virt_drtm_workflow_reset(&s->workflow);
    /* Firmware must start the TPM again before bank discovery can be retried. */
    memset(&s->tcb_hashes, 0, sizeof(s->tcb_hashes));
#ifdef CONFIG_TPM
    s->tpm_ready = false;
    memset(s->active_banks, 0, sizeof(s->active_banks));
    s->active_bank_count = 0;
    s->firmware_hash_algorithm = 0;
#endif
}

static void virt_drtm_reset_exit(Object *obj, ResetType type)
{
#ifdef CONFIG_TPM
    VirtDRTMState *s = VIRT_DRTM(obj);
    Error *local_err = NULL;

    /* Enable locality mediation before the guest runs, without TPM commands. */
    if (!s->tpm_drtm_enabled) {
        if (!tpm_enable_drtm(s->tpm, &local_err)) {
            error_reportf_err(local_err,
                              "virt DRTM cannot enable TPM localities: ");
            exit(1);
        }
        s->tpm_drtm_enabled = true;
    }
#endif
}

static void virt_drtm_init(Object *obj)
{
    VirtDRTMState *s = VIRT_DRTM(obj);

    /* Explicitly document the cold-reset state used by later workflow work. */
    virt_drtm_workflow_init(&s->workflow);
    /* The TPM-selected algorithm is installed lazily after firmware startup. */
    memset(&s->tcb_hashes, 0, sizeof(s->tcb_hashes));
    resettable_state_clear(&s->reset_state);
}

static void virt_drtm_finalize(Object *obj)
{
    VirtDRTMState *s = VIRT_DRTM(obj);
    CPUState *cs;

    if (s->reset_registered) {
        qemu_unregister_resettable(obj);
    }
    /* A failed machine construction is still allowed to roll back routes. */
    if (s->routes_registered && !phase_check(PHASE_MACHINE_READY)) {
        CPU_FOREACH(cs) {
            bool removed = arm_cpu_unregister_firmware_smc_provider(
                ARM_CPU(cs), &virt_drtm_route, virt_drtm_smc, s);

            g_assert(removed);
        }
        s->routes_registered = false;
    }
    if (s->migration_blocker) {
        migrate_del_blocker(&s->migration_blocker);
    }
}

static void virt_drtm_class_init(ObjectClass *oc, const void *data)
{
    ResettableClass *rc = RESETTABLE_CLASS(oc);

    rc->get_state = virt_drtm_get_reset_state;
    rc->phases.enter = virt_drtm_reset_enter;
    rc->phases.exit = virt_drtm_reset_exit;
}

static const TypeInfo virt_drtm_info = {
    .name = TYPE_VIRT_DRTM,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(VirtDRTMState),
    .instance_init = virt_drtm_init,
    .instance_finalize = virt_drtm_finalize,
    .class_init = virt_drtm_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { TYPE_RESETTABLE_INTERFACE },
        { }
    },
};

static void virt_drtm_register_types(void)
{
    type_register_static(&virt_drtm_info);
}
type_init(virt_drtm_register_types)
