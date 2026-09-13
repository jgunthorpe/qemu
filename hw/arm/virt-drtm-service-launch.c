/*
 * Arm virt DRTM production launch bindings
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/arm/virt-drtm.h"

#ifdef CONFIG_TPM
#include "qemu/bswap.h"
#include "qemu/main-loop.h"
#include "hw/arm/virt.h"
#include "hw/arm/virt-drtm-service-launch-internal.h"
#include "virt-drtm-features-internal.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/runstate.h"
#include "target/arm/cpu.h"
#include "target/arm/drtm.h"

typedef struct VirtDRTMServiceLaunch {
    VirtDRTMState *service;
    ARMCPU *cpu;
    VirtDRTMTPMFrontendExecution tpm_execution;
} VirtDRTMServiceLaunch;

typedef struct VirtDRTMMapSnapshot {
    const VirtMachineState *machine;
    VirtDRTMMemoryRegion *regions;
    size_t count;
    size_t capacity;
    bool valid;
} VirtDRTMMapSnapshot;

static bool guest_read(void *opaque, uint64_t address,
                       void *buffer, size_t size)
{
    return address_space_read(&address_space_memory, address,
                              MEMTXATTRS_UNSPECIFIED, buffer, size) ==
        MEMTX_OK;
}

static bool guest_is_ram(void *opaque, uint64_t address, uint64_t size)
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

static VirtDRTMMemoryType map_memory_type(const VirtDRTMMapSnapshot *map,
                                          uint64_t start, uint64_t end,
                                          const MemoryRegion *mr)
{
    const MemMapEntry *flash = &map->machine->memmap[VIRT_FLASH];

    if (memory_region_is_nonvolatile(mr)) {
        return VIRT_DRTM_MEMORY_NON_VOLATILE;
    }
    /* cfi.pflash is an MMIO MemoryRegion, but architecturally it is NVRAM. */
    if (start >= flash->base && end <= flash->base + flash->size) {
        return VIRT_DRTM_MEMORY_NON_VOLATILE;
    }
    if (memory_region_is_ram(mr) && !memory_region_is_rom(mr) &&
        !memory_region_is_ram_device(mr)) {
        return VIRT_DRTM_MEMORY_NORMAL_CACHED;
    }
    return VIRT_DRTM_MEMORY_MMIO;
}

static bool collect_flat_range(Int128 start128, Int128 length128,
                               const MemoryRegion *mr,
                               hwaddr offset_in_region, void *opaque)
{
    VirtDRTMMapSnapshot *map = opaque;
    VirtDRTMMemoryRegion next;
    VirtDRTMMemoryRegion *last;
    VirtDRTMMemoryType type;
    uint64_t start, length, end;

    if (int128_gethi(start128) || int128_gethi(length128)) {
        map->valid = false;
        return true;
    }
    start = int128_get64(start128);
    length = int128_get64(length128);
    if (!length || length > UINT64_MAX - start) {
        map->valid = false;
        return true;
    }
    end = start + length;
    type = map_memory_type(map, start, end, mr);
    start = QEMU_ALIGN_DOWN(start, VIRT_DRTM_PAGE_SIZE);
    if (end > UINT64_MAX - (VIRT_DRTM_PAGE_SIZE - 1)) {
        map->valid = false;
        return true;
    }
    end = ROUND_UP(end, VIRT_DRTM_PAGE_SIZE);
    next = (VirtDRTMMemoryRegion) {
        .address = start,
        .size = end - start,
        .type = type,
        .cacheability = type == VIRT_DRTM_MEMORY_NORMAL_CACHED ? 3 : 0,
    };

    if (map->count) {
        last = &map->regions[map->count - 1];
        if (next.address < last->address + last->size) {
            if (next.type != last->type ||
                next.cacheability != last->cacheability) {
                map->valid = false;
                return true;
            }
            last->size = MAX(last->address + last->size,
                             next.address + next.size) - last->address;
            return false;
        }
        if (next.address == last->address + last->size &&
            next.type == last->type &&
            next.cacheability == last->cacheability) {
            last->size += next.size;
            return false;
        }
    }
    if (map->count == map->capacity) {
        map->valid = false;
        return true;
    }
    map->regions[map->count++] = next;
    return false;
}

static VirtDRTMResult snapshot_address_map(void *opaque,
                                           VirtDRTMMemoryRegion **regions,
                                           size_t *count)
{
    VirtDRTMServiceLaunch *launch = opaque;
    const VirtMachineState *machine =
        container_of(launch->service, VirtMachineState, drtm_state);
    VirtDRTMMapSnapshot map;
    RCU_READ_LOCK_GUARD();
    FlatView *view = address_space_to_flatview(&address_space_memory);

    memset(&map, 0, sizeof(map));
    map.machine = machine;
    map.capacity = view->nr;
    map.regions = g_try_new(VirtDRTMMemoryRegion, map.capacity);
    if (!map.regions) {
        return VIRT_DRTM_WORKFLOW_OUT_OF_RESOURCE;
    }
    map.valid = true;
    flatview_for_each_range(view, collect_flat_range, &map);
    if (!map.valid || !map.count) {
        g_free(map.regions);
        return VIRT_DRTM_INTERNAL_ERROR;
    }
    *regions = map.regions;
    *count = map.count;
    return VIRT_DRTM_SUCCESS;
}

static bool secondary_pes_off(ARMCPU *caller)
{
    CPUState *cs;

    CPU_FOREACH(cs) {
        if (cs != CPU(caller) && ARM_CPU(cs)->power_state != PSCI_OFF) {
            return false;
        }
    }
    return true;
}

static bool platform_debug_or_trace_enabled(void)
{
    /*
     * QEMU permits an external debugger to attach and alter guest state while
     * the VM is running.  That capability is dynamic and is not disabled by a
     * DRTM launch, so R44180/R44190 require the conservative enabled value
     * regardless of whether a debugger is attached at this instant.
     */
    return true;
}

static bool platform_nonsecure_lifecycle(void)
{
    /*
     * The virt machine models a deployed platform only: it has no
     * manufacturing, provisioning, RMA, end-of-life, or runtime lifecycle
     * transition state.  R44200/R45060 are therefore represented by the
     * deployment-state value.
     */
    return false;
}

static bool launch_no_active(void *opaque, bool *no_active, Error **errp)
{
    VirtDRTMServiceLaunch *launch = opaque;

    return tpm_drtm_no_active_locality(launch->service->tpm,
                                        no_active, errp);
}

static bool launch_prepare_tpm(
    void *opaque, const VirtDRTMMeasurementManifest *manifest, Error **errp)
{
    VirtDRTMServiceLaunch *launch = opaque;

    return virt_drtm_tpm_frontend_execution_init(
        &launch->tpm_execution, manifest, launch->service->tpm, errp);
}

static bool launch_open_localities(void *opaque, Error **errp)
{
    VirtDRTMServiceLaunch *launch = opaque;

    return tpm_drtm_open_localities(launch->service->tpm, errp);
}

static VirtDRTMTPMResult launch_hash_dce(
    void *opaque, const VirtDRTMMeasurementManifest *manifest, Error **errp)
{
    VirtDRTMServiceLaunch *launch = opaque;

    g_assert(launch->tpm_execution.execution.manifest == manifest);
    return virt_drtm_tpm_frontend_execute_hash(&launch->tpm_execution, errp);
}

static VirtDRTMTPMResult launch_extend_dcrtm(
    void *opaque, const VirtDRTMMeasurementManifest *manifest, Error **errp)
{
    VirtDRTMServiceLaunch *launch = opaque;

    g_assert(launch->tpm_execution.execution.manifest == manifest);
    return virt_drtm_tpm_frontend_execute_dcrtm_extends(
        &launch->tpm_execution, errp);
}

static VirtDRTMTPMResult launch_extend_dce(
    void *opaque, const VirtDRTMMeasurementManifest *manifest, Error **errp)
{
    VirtDRTMServiceLaunch *launch = opaque;

    g_assert(launch->tpm_execution.execution.manifest == manifest);
    return virt_drtm_tpm_frontend_execute_dce_extends(
        &launch->tpm_execution, errp);
}

static bool launch_write(void *opaque, uint64_t address, const uint8_t *data,
                         size_t size, Error **errp)
{
    if (address_space_write(&address_space_memory, address,
                            MEMTXATTRS_UNSPECIFIED, data, size) != MEMTX_OK) {
        error_setg(errp, "cannot write DRTM DLME data to guest RAM");
        return false;
    }
    return true;
}

static bool launch_close_locality3(void *opaque,
                                   TPMDRTMLocalityCloseResult *result,
                                   Error **errp)
{
    VirtDRTMServiceLaunch *launch = opaque;

    return tpm_drtm_close_locality(launch->service->tpm, 3, result, errp);
}

static bool launch_activate_locality2(void *opaque, Error **errp)
{
    VirtDRTMServiceLaunch *launch = opaque;

    return tpm_drtm_activate_locality2(launch->service->tpm, errp);
}

static bool launch_enter_dlme(void *opaque, uint64_t dlme_address,
                              uint64_t data_offset, uint64_t entry_address,
                              Error **errp)
{
    VirtDRTMServiceLaunch *launch = opaque;
    ARMDRTMEntryResult result = arm_drtm_enter_dlme(
        launch->cpu, dlme_address, data_offset, entry_address);

    if (result != ARM_DRTM_ENTRY_OK) {
        error_setg(errp, "cannot configure DRTM DLME CPU entry state (%d)",
                   result);
        return false;
    }
    return true;
}

static void launch_request_reset(void *opaque)
{
    qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
}

static const VirtDRTMServiceLaunchOps service_ops = {
    .read = guest_read,
    .is_ram = guest_is_ram,
    .alloc = g_try_malloc,
    .snapshot_address_map = snapshot_address_map,
    .prepare_tpm = launch_prepare_tpm,
    .launch = {
        .no_active_locality = launch_no_active,
        .open_localities = launch_open_localities,
        .hash_dce = launch_hash_dce,
        .extend_dcrtm = launch_extend_dcrtm,
        .extend_dce = launch_extend_dce,
        .write = launch_write,
        .close_locality3 = launch_close_locality3,
        .activate_locality2 = launch_activate_locality2,
        .enter_dlme = launch_enter_dlme,
        .request_cold_reset = launch_request_reset,
    },
    .debug_or_trace_enabled = true,
    .nonsecure_lifecycle = false,
};


#endif
#ifdef CONFIG_TPM
VirtDRTMLaunchResult virt_drtm_service_launch(VirtDRTMState *s, ARMCPU *cpu,
                                               uint64_t parameters_address,
                                               Error **errp)
{
    VirtDRTMServiceLaunch launch = { .service = s, .cpu = cpu };
    VirtDRTMServiceLaunchOps ops = service_ops;

    g_assert(cpu);
    ops.debug_or_trace_enabled = platform_debug_or_trace_enabled();
    ops.nonsecure_lifecycle = platform_nonsecure_lifecycle();
    return virt_drtm_service_launch_with_ops(
        s, parameters_address,
        CPU(cpu) == current_cpu && is_a64(&cpu->env) &&
            !arm_is_secure(&cpu->env),
        CPU(cpu) == first_cpu, secondary_pes_off(cpu),
        VIRT_DRTM_ADDRESS_MAP_MAX_REGIONS, &ops, &launch, errp);
}
#else
VirtDRTMLaunchResult virt_drtm_service_launch(VirtDRTMState *s, ARMCPU *cpu,
                                               uint64_t parameters_address,
                                               Error **errp)
{
    return (VirtDRTMLaunchResult) {
        .result = VIRT_DRTM_NOT_SUPPORTED,
        .stage = VIRT_DRTM_LAUNCH_PROBE,
    };
}
#endif
