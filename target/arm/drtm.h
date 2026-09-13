/*
 * Arm Dynamic Root of Trust for Measurement CPU entry
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_ARM_DRTM_H
#define TARGET_ARM_DRTM_H

#include "cpu-qom.h"

typedef enum ARMDRTMEntryResult {
    ARM_DRTM_ENTRY_OK,
    ARM_DRTM_ENTRY_INVALID_STATE,
    ARM_DRTM_ENTRY_INVALID_ADDRESS,
} ARMDRTMEntryResult;

/**
 * arm_drtm_enter_dlme: configure the current PE for DLME entry
 * @cpu: current CPU, executing a Normal-world firmware call
 * @region_pa: physical base address of the DLME region
 * @data_offset: offset of the DLME data from @region_pa
 * @entry_pa: physical entry address in the DLME image
 *
 * Configure @cpu with the PSCI CPU_ON initial state required by DEN0113,
 * with the DRTM-specific overrides for execution state, EL and arguments.
 * The caller is responsible for DLME layout/range validation and for all
 * platform policy, including boot-PE and secondary-PE checks.
 *
 * All conditions which can fail are checked before architectural state is
 * changed.  On success the current translation block is forced to exit.
 */
ARMDRTMEntryResult arm_drtm_enter_dlme(ARMCPU *cpu, uint64_t region_pa,
                                       uint64_t data_offset,
                                       uint64_t entry_pa);

#endif /* TARGET_ARM_DRTM_H */
