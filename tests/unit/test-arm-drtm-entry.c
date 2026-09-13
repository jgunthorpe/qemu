/*
 * Arm DRTM target CPU entry tests
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "target/arm/cpu.h"
#include "target/arm/internals.h"
#include "target/arm/drtm.h"
#include "system/tcg.h"

static void init_cpu(ARMCPU *cpu, int el, bool aarch64, bool have_el2)
{
    CPUARMState *env = &cpu->env;

    memset(cpu, 0, sizeof(*cpu));
    current_cpu = &cpu->parent_obj;
    set_feature(env, ARM_FEATURE_AARCH64);
    FIELD_DP64_IDREG(&cpu->isar, ID_AA64PFR1, NMI, 1);
    if (have_el2) {
        set_feature(env, ARM_FEATURE_EL2);
    }
    env->aarch64 = aarch64;
    if (aarch64) {
        pstate_write(env, aarch64_pstate_mode(el, true));
    } else {
        env->uncached_cpsr = ARM_CPU_MODE_SVC;
    }

    for (unsigned int i = 0; i < ARRAY_SIZE(env->xregs); i++) {
        env->xregs[i] = UINT64_C(0xfeed000000000000) | i;
    }
    for (unsigned int i = 0; i < ARRAY_SIZE(env->sp_el); i++) {
        env->sp_el[i] = UINT64_C(0xcafe000000000000) | i;
    }
    env->pc = UINT64_C(0x12345678);
    env->exclusive_addr = UINT64_C(0x1000);
    memset(&env->hflags, 0xff, sizeof(env->hflags));
    env->cp15.sctlr_el[1] = SCTLR_M | SCTLR_C | SCTLR_I | SCTLR_EE |
                            SCTLR_A;
    env->cp15.sctlr_el[2] = SCTLR_M | SCTLR_C | SCTLR_I | SCTLR_EE |
                            SCTLR_A;
    for (unsigned int i = 1; i <= 2; i++) {
        env->cp15.ttbr0_el[i] = UINT64_C(0x1111000000000000) | i;
        env->cp15.ttbr1_el[i] = UINT64_C(0x2222000000000000) | i;
        env->cp15.tcr_el[i] = UINT64_C(0x3333000000000000) | i;
        env->cp15.mair_el[i] = UINT64_C(0x4444000000000000) | i;
    }
}

static void assert_entry_state(bool have_el2)
{
    ARMCPU cpu;
    CPUARMState *env = &cpu.env;
    const uint64_t region_pa = UINT64_C(0x40000000);
    const uint64_t data_offset = UINT64_C(0x20000);
    const uint64_t entry_pa = UINT64_C(0x40001000);
    CPUARMTBFlags stale_hflags;
    uint64_t ttbr0, ttbr1, tcr, mair;
    int target_el = have_el2 ? 2 : 1;

    init_cpu(&cpu, 1, true, have_el2);
    stale_hflags = env->hflags;
    ttbr0 = env->cp15.ttbr0_el[target_el];
    ttbr1 = env->cp15.ttbr1_el[target_el];
    tcr = env->cp15.tcr_el[target_el];
    mair = env->cp15.mair_el[target_el];
    g_assert_cmpint(arm_drtm_enter_dlme(&cpu, region_pa, data_offset,
                                       entry_pa), ==, ARM_DRTM_ENTRY_OK);

    g_assert_true(env->aarch64);
    g_assert_cmpint(arm_current_el(env), ==, target_el);
    g_assert_cmphex(pstate_read(env) & PSTATE_DAIF, ==, PSTATE_DAIF);
    g_assert_cmphex(pstate_read(env) & PSTATE_ALLINT, ==, PSTATE_ALLINT);
    g_assert_cmphex(env->cp15.sctlr_el[target_el] &
                    (SCTLR_M | SCTLR_C | SCTLR_I | SCTLR_EE), ==, 0);
    g_assert_cmphex(env->cp15.sctlr_el[target_el] & SCTLR_A, ==, SCTLR_A);
    g_assert_cmphex(env->cp15.ttbr0_el[target_el], ==, ttbr0);
    g_assert_cmphex(env->cp15.ttbr1_el[target_el], ==, ttbr1);
    g_assert_cmphex(env->cp15.tcr_el[target_el], ==, tcr);
    g_assert_cmphex(env->cp15.mair_el[target_el], ==, mair);
    g_assert_cmphex(env->xregs[0], ==, region_pa);
    g_assert_cmphex(env->xregs[1], ==, data_offset);
    for (unsigned int i = 2; i < ARRAY_SIZE(env->xregs); i++) {
        g_assert_cmphex(env->xregs[i], ==, 0);
    }
    for (unsigned int i = 0; i < ARRAY_SIZE(env->sp_el); i++) {
        g_assert_cmphex(env->sp_el[i], ==, 0);
    }
    g_assert_cmphex(env->pc, ==, entry_pa);
    g_assert_cmphex(env->exclusive_addr, ==, UINT64_MAX);
    g_assert_cmpint(memcmp(&env->hflags, &stale_hflags,
                           sizeof(env->hflags)), !=, 0);
    g_assert_true(cpu_test_interrupt(&cpu.parent_obj,
                                     CPU_INTERRUPT_EXITTB));
}

static void test_entry_el1(void)
{
    assert_entry_state(false);
}

static void test_entry_el2(void)
{
    assert_entry_state(true);
}

static void assert_rejected_unchanged(ARMCPU *cpu, uint64_t region_pa,
                                      uint64_t data_offset, uint64_t entry_pa,
                                      ARMDRTMEntryResult expected)
{
    ARMCPU before = *cpu;

    g_assert_cmpint(arm_drtm_enter_dlme(cpu, region_pa, data_offset,
                                       entry_pa), ==, expected);
    g_assert_cmpmem(cpu, sizeof(*cpu), &before, sizeof(before));
}

static void test_rejection_is_atomic(void)
{
    ARMCPU cpu;

    init_cpu(&cpu, 1, false, false);
    assert_rejected_unchanged(&cpu, 0x40000000, 0x20000, 0x40001000,
                              ARM_DRTM_ENTRY_INVALID_STATE);

    init_cpu(&cpu, 0, true, false);
    assert_rejected_unchanged(&cpu, 0x40000000, 0x20000, 0x40001000,
                              ARM_DRTM_ENTRY_INVALID_STATE);

    init_cpu(&cpu, 1, true, false);
    assert_rejected_unchanged(&cpu, 0x40000000, 0x20000, 0x40001002,
                              ARM_DRTM_ENTRY_INVALID_ADDRESS);

    /* The zero PARange test value implements a 32-bit physical address. */
    init_cpu(&cpu, 1, true, false);
    assert_rejected_unchanged(&cpu, UINT64_C(1) << 32, 0, 0x40001000,
                              ARM_DRTM_ENTRY_INVALID_ADDRESS);

    init_cpu(&cpu, 1, true, false);
    assert_rejected_unchanged(&cpu, 0xfffff000, 0x1000, 0x40001000,
                              ARM_DRTM_ENTRY_INVALID_ADDRESS);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    tcg_allowed = true;
    g_test_add_func("/arm/drtm-entry/el1", test_entry_el1);
    g_test_add_func("/arm/drtm-entry/el2", test_entry_el2);
    g_test_add_func("/arm/drtm-entry/rejection-atomic",
                    test_rejection_is_atomic);
    return g_test_run();
}
