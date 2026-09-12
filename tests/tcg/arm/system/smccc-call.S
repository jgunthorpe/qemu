/*
 * Register setup and capture for the PSCI/SMCCC system test.
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifdef __aarch64__

        .text
        .align  2
        .global smccc_call
        .type   smccc_call, %function
smccc_call:
        stp     x19, x20, [sp, #-16]!
        mov     x19, x2
        mov     x20, x3
        mov     x2, #-3
        mov     x3, #-4
        mov     x4, #-5
        mov     x5, #-6
        mov     x6, #-7
        mov     x7, #-8
        mov     x8, #-9
        mov     x9, #-10
        mov     x10, #-11
        mov     x11, #-12
        mov     x12, #-13
        mov     x13, #-14
        mov     x14, #-15
        mov     x15, #-16
        mov     x16, #-17
        mov     x17, #-18
        cbnz    x20, 1f
        hvc     #0
        b       2f
1:
        smc     #0
2:
        stp     x0, x1, [x19]
        stp     x2, x3, [x19, #16]
        stp     x4, x5, [x19, #32]
        stp     x6, x7, [x19, #48]
        stp     x8, x9, [x19, #64]
        stp     x10, x11, [x19, #80]
        stp     x12, x13, [x19, #96]
        stp     x14, x15, [x19, #112]
        stp     x16, x17, [x19, #128]
        ldp     x19, x20, [sp], #16
        ret
        .size   smccc_call, . - smccc_call

#else

        .syntax unified
        .text
        .align  2
        .global smccc_call
        .type   smccc_call, %function
smccc_call:
        push    {r4-r12, lr}
        mov     r8, r2
        mov     r9, r3
        mvn     r2, #2
        mvn     r3, #3
        mvn     r4, #4
        mvn     r5, #5
        mvn     r6, #6
        mvn     r7, #7
        cmp     r9, #0
        bne     1f
        hvc     #0
        b       2f
1:
        smc     #0
2:
        stmia   r8, {r0-r7}
        pop     {r4-r12, pc}
        .size   smccc_call, . - smccc_call

#endif
