/*
 * In-process firmware SMCCC provider registry
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/bitops.h"
#include "qemu/host-utils.h"
#include "firmware-smc.h"

static bool route_matches(const ARMFirmwareSMCRoute *route,
                          ARMFirmwareSMCConduit conduit, uint32_t function)
{
    uint32_t offset;

    if (route->conduit != conduit) {
        return false;
    }

    offset = function - route->function_base;
    return offset < 64 && extract64(route->function_mask, offset, 1);
}

void arm_firmware_smc_registry_init(ARMFirmwareSMCRegistry *registry)
{
    registry->providers =
        g_array_new(false, false, sizeof(ARMFirmwareSMCProvider));
    registry->frozen = false;
}

void arm_firmware_smc_registry_destroy(ARMFirmwareSMCRegistry *registry)
{
    g_clear_pointer(&registry->providers, g_array_unref);
    registry->frozen = true;
}

void arm_firmware_smc_registry_freeze(ARMFirmwareSMCRegistry *registry)
{
    registry->frozen = true;
}

const ARMFirmwareSMCProvider *arm_firmware_smc_registry_lookup(
    const ARMFirmwareSMCRegistry *registry, ARMFirmwareSMCConduit conduit,
    uint32_t function)
{
    unsigned int i;

    for (i = 0; i < registry->providers->len; i++) {
        const ARMFirmwareSMCProvider *provider =
            &g_array_index(registry->providers, ARMFirmwareSMCProvider, i);

        if (route_matches(&provider->route, conduit, function)) {
            return provider;
        }
    }
    return NULL;
}

bool arm_firmware_smc_registry_register(
    ARMFirmwareSMCRegistry *registry, const ARMFirmwareSMCRoute *route,
    ARMFirmwareSMCHandler *handler, void *opaque, Error **errp)
{
    ARMFirmwareSMCProvider provider;
    uint64_t functions;
    int highest;

    if (registry->frozen) {
        error_setg(errp, "firmware SMCCC provider registry is frozen");
        return false;
    }
    if (!route) {
        error_setg(errp, "firmware SMCCC provider requires a route");
        return false;
    }
    if (!handler) {
        error_setg(errp, "firmware SMCCC provider requires a handler");
        return false;
    }
    if (route->conduit != ARM_FIRMWARE_SMCCC_CONDUIT_SMC &&
        route->conduit != ARM_FIRMWARE_SMCCC_CONDUIT_HVC) {
        error_setg(errp, "invalid firmware SMCCC conduit %u", route->conduit);
        return false;
    }
    if (!route->function_mask) {
        error_setg(errp, "firmware SMCCC provider has no function IDs");
        return false;
    }

    highest = 63 - clz64(route->function_mask);
    if (route->function_base > UINT32_MAX - highest) {
        error_setg(errp, "firmware SMCCC function-ID range wraps");
        return false;
    }

    functions = route->function_mask;
    while (functions) {
        unsigned int bit = ctz64(functions);

        if (arm_firmware_smc_registry_lookup(registry, route->conduit,
                                             route->function_base + bit)) {
            error_setg(errp,
                       "firmware SMCCC provider function 0x%08x overlaps",
                       route->function_base + bit);
            return false;
        }
        functions &= functions - 1;
    }

    provider = (ARMFirmwareSMCProvider) {
        .route = *route,
        .handler = handler,
        .opaque = opaque,
    };
    g_array_append_val(registry->providers, provider);
    return true;
}
