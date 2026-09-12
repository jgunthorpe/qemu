/*
 * In-process firmware SMCCC provider dispatch
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"
#include "hw/core/qdev.h"
#include "cpu.h"
#include "internals.h"

static const ARMFirmwareSMCProvider *find_provider(ARMCPU *cpu, int excp_type)
{
    CPUARMState *env = &cpu->env;
    ARMFirmwareSMCConduit conduit;
    uint32_t function;

    if (arm_feature(env, ARM_FEATURE_EL3) || arm_is_secure(env) ||
        arm_current_el(env) == 0) {
        return NULL;
    }

    switch (excp_type) {
    case EXCP_SMC:
        conduit = ARM_FIRMWARE_SMCCC_CONDUIT_SMC;
        break;
    case EXCP_HVC:
        conduit = ARM_FIRMWARE_SMCCC_CONDUIT_HVC;
        break;
    default:
        return NULL;
    }

    function = is_a64(env) ? env->xregs[0] : env->regs[0];
    return arm_firmware_smc_registry_lookup(&cpu->firmware_smc_registry,
                                            conduit, function);
}

bool arm_cpu_register_firmware_smc_provider(
    ARMCPU *cpu, const ARMFirmwareSMCRoute *route,
    ARMFirmwareSMCHandler *handler, void *opaque, Error **errp)
{
    if (phase_check(PHASE_MACHINE_READY)) {
        arm_firmware_smc_registry_freeze(&cpu->firmware_smc_registry);
        error_setg(errp,
                   "firmware SMCCC providers must be registered during machine initialization");
        return false;
    }
    return arm_firmware_smc_registry_register(&cpu->firmware_smc_registry,
                                              route, handler, opaque, errp);
}

bool arm_is_firmware_smc_call(ARMCPU *cpu, int excp_type)
{
    return find_provider(cpu, excp_type) != NULL;
}

void arm_handle_firmware_smc_call(ARMCPU *cpu)
{
    const ARMFirmwareSMCProvider *provider =
        find_provider(cpu, CPU(cpu)->exception_index);
    bool locked = bql_locked();

    g_assert(provider);
    if (!locked) {
        bql_lock();
    }
    provider->handler(cpu, provider->opaque);
    if (!locked) {
        bql_unlock();
    }
}
