/*
 * Arm Dynamic Root of Trust for Measurement CPU entry
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "drtm.h"
#include "system/tcg.h"

static bool arm_drtm_pa_valid(uint64_t address, unsigned int pamax)
{
    return pamax == 64 || address < (UINT64_C(1) << pamax);
}

ARMDRTMEntryResult arm_drtm_enter_dlme(ARMCPU *cpu, uint64_t region_pa,
                                       uint64_t data_offset,
                                       uint64_t entry_pa)
{
    CPUState *cs = &cpu->parent_obj;
    CPUARMState *env = &cpu->env;
    unsigned int pamax;
    uint64_t pstate;
    int current_el;
    int target_el;

    /*
     * DRTM_DYNAMIC_LAUNCH is an SMC64 call from the Normal world.  Checking
     * that invariant here also makes it impossible to partially change an
     * AArch32 or malformed exception-level state.
     */
    if (!tcg_enabled() || current_cpu != cs ||
        !arm_feature(env, ARM_FEATURE_AARCH64) ||
        !is_a64(env) || arm_is_secure(env)) {
        return ARM_DRTM_ENTRY_INVALID_STATE;
    }

    current_el = arm_current_el(env);
    if (current_el < 1 || current_el > 2 ||
        (current_el == 2 && !arm_feature(env, ARM_FEATURE_EL2))) {
        return ARM_DRTM_ENTRY_INVALID_STATE;
    }

    /* EL3 is Secure firmware; the highest implemented Non-secure EL is EL2. */
    target_el = arm_feature(env, ARM_FEATURE_EL2) ? 2 : 1;

    pamax = arm_pamax(cpu);
    if ((entry_pa & 3) || !arm_drtm_pa_valid(region_pa, pamax) ||
        !arm_drtm_pa_valid(entry_pa, pamax) ||
        data_offset > UINT64_MAX - region_pa ||
        !arm_drtm_pa_valid(region_pa + data_offset, pamax)) {
        return ARM_DRTM_ENTRY_INVALID_ADDRESS;
    }

    arm_call_pre_el_change_hook(cpu);

    /*
     * PSCI makes the general-purpose registers other than its context ID
     * architecturally UNKNOWN.  For reproducibility, QEMU's CPU_ON path gets
     * zeroes from cpu_reset(); use the same deterministic model policy here.
     * X0 and X1 are then replaced by the DEN0113 values.
     *
     * System registers for which CPU_ON specifies UNKNOWN are retained as a
     * separate deterministic model policy: this focused transition changes
     * only architecturally required fields.  That retention is not part of
     * the DEN0113 software contract.
     */
    memset(env->xregs, 0, sizeof(env->xregs));
    memset(env->sp_el, 0, sizeof(env->sp_el));
    env->xregs[0] = region_pa;
    env->xregs[1] = data_offset;

    /*
     * PSCI CPU_ON enters with the MMU and caches disabled.  DEN0113 R45450
     * additionally fixes the execution state, EL and byte order, while
     * R45460 and R45470 require all asynchronous and debug masks to be set.
     */
    env->aarch64 = true;
    env->cp15.sctlr_el[target_el] &=
        ~(SCTLR_M | SCTLR_C | SCTLR_I | SCTLR_EE);
    pstate = aarch64_pstate_mode(target_el, true) | PSTATE_DAIF;
    if (cpu_isar_feature(aa64_nmi, cpu)) {
        pstate |= PSTATE_ALLINT;
    }
    pstate_write(env, pstate);
    arm_clear_exclusive(env);
    env->pc = entry_pa;

    arm_call_el_change_hook(cpu);
    arm_rebuild_hflags(env);

    /*
     * TCG has no separate instruction-cache contents to invalidate for
     * R45310: writes to translated RAM already invalidate affected TBs.
     * Exit only this CPU's current TB so the new PC and hflags take effect;
     * a global translation-cache flush would be unnecessary.
     */
    cpu_set_interrupt(cs, CPU_INTERRUPT_EXITTB);

    return ARM_DRTM_ENTRY_OK;
}
