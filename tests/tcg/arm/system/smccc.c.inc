/*
 * Test QEMU's in-process PSCI/SMCCC firmware interface.
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>
#include <stdint.h>

#define SMCCC_VERSION_FN       0x80000000U
#define SMCCC_VERSION_1_1      0x00010001U
#define PSCI_VERSION_FN        0x84000000U
#define PSCI_FEATURES_FN       0x8400000aU
#define PSCI_NOT_SUPPORTED     ((uintptr_t)-1)
#define UNKNOWN_PSCI_FN        0x8400ffffU

typedef struct CallResult {
    uintptr_t reg[18];
} CallResult;

#ifdef USE_SMC
#define USE_SMC_VALUE 1
#else
#define USE_SMC_VALUE 0
#endif

void smccc_call(uintptr_t function, uintptr_t argument, CallResult *result,
                uintptr_t use_smc);

static int check(const char *name, uint32_t function, uintptr_t argument,
                 uintptr_t expected)
{
    CallResult result;
    unsigned int i;
#ifdef __aarch64__
    const unsigned int last_preserved_reg = 17;
#else
    const unsigned int last_preserved_reg = 7;
#endif

    smccc_call(function, argument, &result, USE_SMC_VALUE);
    if (result.reg[0] != expected) {
        ml_printf("FAIL: %s returned %lx, expected %lx\n", name,
                  (unsigned long)result.reg[0], (unsigned long)expected);
        return 1;
    }
    if (result.reg[1] != argument) {
        ml_printf("FAIL: %s changed register 1\n", name);
        return 1;
    }
    for (i = 2; i <= last_preserved_reg; i++) {
        if (result.reg[i] != ~(uintptr_t)i) {
            ml_printf("FAIL: %s changed register %u\n", name, i);
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    int failures = 0;

    failures += check("SMCCC_VERSION", SMCCC_VERSION_FN, ~(uintptr_t)1,
                      SMCCC_VERSION_1_1);
    failures += check("PSCI_FEATURES(SMCCC_VERSION)", PSCI_FEATURES_FN,
                      SMCCC_VERSION_FN, 0);
    failures += check("PSCI_VERSION", PSCI_VERSION_FN, ~(uintptr_t)1,
                      0x00010001U);
    failures += check("unknown PSCI function", UNKNOWN_PSCI_FN,
                      ~(uintptr_t)1,
                      PSCI_NOT_SUPPORTED);

    if (!failures) {
        ml_printf("SMCCC/PSCI checks passed\n");
    }
    return failures != 0;
}
