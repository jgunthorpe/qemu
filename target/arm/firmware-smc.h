/*
 * In-process firmware SMCCC provider registry
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_ARM_FIRMWARE_SMC_H
#define TARGET_ARM_FIRMWARE_SMC_H

#include "qemu/typedefs.h"

typedef struct ArchCPU ARMCPU;
typedef void ARMFirmwareSMCHandler(ARMCPU *cpu, void *opaque);

typedef enum ARMFirmwareSMCConduit {
    ARM_FIRMWARE_SMCCC_CONDUIT_SMC = 1,
    ARM_FIRMWARE_SMCCC_CONDUIT_HVC = 2,
} ARMFirmwareSMCConduit;

/*
 * An exact set of at most 64 SMCCC function identifiers.  Bit N in
 * @function_mask selects @function_base + N.
 */
typedef struct ARMFirmwareSMCRoute {
    ARMFirmwareSMCConduit conduit;
    uint32_t function_base;
    uint64_t function_mask;
} ARMFirmwareSMCRoute;

typedef struct ARMFirmwareSMCProvider {
    ARMFirmwareSMCRoute route;
    ARMFirmwareSMCHandler *handler;
    void *opaque;
} ARMFirmwareSMCProvider;

typedef struct ARMFirmwareSMCRegistry {
    GArray *providers;
    bool frozen;
} ARMFirmwareSMCRegistry;

void arm_firmware_smc_registry_init(ARMFirmwareSMCRegistry *registry);
void arm_firmware_smc_registry_destroy(ARMFirmwareSMCRegistry *registry);
void arm_firmware_smc_registry_freeze(ARMFirmwareSMCRegistry *registry);
bool arm_firmware_smc_registry_register(
    ARMFirmwareSMCRegistry *registry, const ARMFirmwareSMCRoute *route,
    ARMFirmwareSMCHandler *handler, void *opaque, Error **errp);
bool arm_firmware_smc_registry_unregister(
    ARMFirmwareSMCRegistry *registry, const ARMFirmwareSMCRoute *route,
    ARMFirmwareSMCHandler *handler, void *opaque);
const ARMFirmwareSMCProvider *arm_firmware_smc_registry_lookup(
    const ARMFirmwareSMCRegistry *registry, ARMFirmwareSMCConduit conduit,
    uint32_t function);

#endif
