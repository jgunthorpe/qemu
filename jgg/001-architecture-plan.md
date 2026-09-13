# Architecture plan: emulation first

> **Superseded plan.** This document predates the TPM-backed DEN0113 v1.4B
> implementation.  See
> [035-current-implementation.md](035-current-implementation.md) for the
> shipped software contract.  Statements below about version 1.1, no required
> TPM, optional PCR updates, and future hardware enforcement are historical.

## Scope

The basic implementation is a QEMU firmware-interface test model. Its job is
to emulate DRTM SMC behavior and the DLME transition closely enough to run a
DRTM workflow in a VM. It does not try to turn the QEMU process or virtual
machine into a security boundary.

The basic `x-drtm=on` mode requires:

- TCG;
- AArch64 CPUs;
- `secure=off`;
- the SMC conduit selected by `virtualization=on`; and
- sufficient guest RAM for the ACS launch region.

It does not require SMMUv3, special DMA topology, GIC quiescing, or a TPM.
Those dependencies belong only to later optional phases.

## Existing SMC path and dispatch seam

An SMC reaches `HELPER(pre_smc)` in `target/arm/tcg/op_helper.c`. With QEMU
providing PSCI through SMC, `arm_cpu_do_interrupt()` offers every such call to
the in-process PSCI handler; an unknown DRTM FID currently becomes
`PSCI_RET_NOT_SUPPORTED`.

Add a small generic firmware-SMC provider alongside PSCI:

```text
guest SMC
   -> immutable conduit/FID match in target/arm
   -> registered QEMU firmware handler under the BQL
   -> existing PSCI fallback
   -> architectural SMC exception if neither applies
```

Store immutable conduit and exact FID range/bitmap data in `ARMCPU`, so
`pre_smc` does not call arbitrary device code. The callback is invoked only in
the later exception path. `target/arm` must not include virt/DRTM headers.

## DRTM service object

Create a non-MMIO QOM object owned by `VirtMachineState`. It holds:

- the selected 1.1 compatibility profile and FEATURES values;
- idle/launched/protected/unprotected state;
- locality-open/closed flags modeled at the DRTM API level;
- the sticky DRTM error value;
- a copied, decoded launch parameter block;
- generated DLME data and event-log buffers; and
- optional TCB hashes.

The object registers its handler on every initial CPU. CPU hotplug can remain
unsupported in the experimental mode. Migration is outside this project; add
a migration blocker rather than designing VMState.

## Concrete SMC ABI

The local ACS uses these SMC64 FIDs:

| FID | Function | Basic behavior |
|---:|---|---|
| `0xc4000110` | VERSION | report the pinned 1.1 profile |
| `0xc4000111` | FEATURES | report modeled workflow capabilities |
| `0xc4000113` | UNPROTECT_MEMORY | change modeled protected state |
| `0xc4000114` | DYNAMIC_LAUNCH | validate, build data, and enter the DLME |
| `0xc4000115` | CLOSE_LOCALITY | update modeled locality state |
| `0xc4000116` | GET_ERROR | return the sticky emulated error |
| `0xc4000117` | SET_ERROR | validate and update the error |
| `0xc4000118` | SET_TCB_HASH | optional core fidelity patch |
| `0xc4000119` | LOCK_TCB_HASH | optional core fidelity patch |
| `0xc400011a` | ENABLE_SECURE_INTERRUPTS | emulate state/return only, if exposed |

FEATURES must still distinguish function queries from feature-ID queries and
return X1 values according to DEN0113. In workflow mode the DMA feature
advertises only complete protection, with a zero maximum protected-region
count. Region protection and its table are not part of the platform contract.
Complete protection is a modeled capability; it is not an assertion that
device DMA is blocked. This limitation must be visible in the machine
documentation and trace output.

## Parameter validation

Decode the 88-byte revision-2 parameter block explicitly using fixed-width
little-endian loads. Never cast guest memory directly to a host structure.

The parser validates revision/reserved fields, launch features, alignment,
checked address/size arithmetic, region/image/data containment and overlap,
entry point, optional DCE fields, and protection-table syntax. Verify that
referenced spans are ordinary accessible RAM. Full device/alias/security
classification is intentionally deferred.

Copy the parameter block once before validation. For the basic workflow, copy
the DLME/DCE bytes used for software measurement immediately before hashing
and handoff while the calling vCPU is stopped under the BQL. This provides
deterministic emulation, not DMA-resistant measurement.

## Launch-data builder

Build a revision-1 DLME data block in a bounded host buffer, then perform one
checked write into the guest data region. Include:

- header and aligned section offsets/sizes;
- the complete-protection sentinel descriptor as modeled metadata;
- a simple sorted address map derived from configured virt RAM/platform ranges;
- a crypto-agile TCG event log; and
- enough ACPI/TCB data for the selected ACS tests.

For the first workflow, ACPI may be copied from the firmware/guest-visible
tables and labeled untrusted test metadata. A later optional patch can source
the exact QEMU ACPI builder bytes and provide stronger provenance.

All sizes and offsets remain overflow checked even though this is not a
security boundary; malformed guest input must not crash or corrupt QEMU.

## Software measurement and event log

Use QEMU's qcrypto API to calculate SHA-256 measurements. Emit the Spec ID
Event03 header and PCR_EVENT2 records in the pinned ACS-compatible order.

The basic mode does not issue TPM commands and does not claim that PCRs were
extended. Its event log is a deterministic description of modeled launch
measurements. FEATURES should describe this as the workflow profile rather
than claiming TPM-backed hashing. The optional vTPM phase later consumes the
same digest/event list and extends virtual PCRs.

## CPU handoff

Do not use `arm_set_cpu_on()` for the current CPU and do not call full
`cpu_reset()`. Add a focused target helper which applies the expected DRTM
entry state:

- AArch64 at the selected non-secure EL;
- required endianness and SCTLR/PSTATE controls;
- D/A/I/F masks;
- X0 = DLME region base;
- X1 = DLME data offset;
- PC = validated image entry; and
- rebuilt hflags plus a forced TB exit.

Boot-PE identity and secondary-PE checks remain in the machine service. Treat
architecturally UNKNOWN registers consistently so the ACS DLME can restore its
saved translation state.

## Basic launch transaction

The emulation-first launch path is deliberately simple:

1. Check caller, boot PE, secondary PE state, service state, and feature bits.
2. Copy and validate parameters and referenced RAM.
3. Build launch metadata and software measurement/event data.
4. Write the complete DLME data block.
5. Mark the service logically protected and reset modeled locality state.
6. Enter the DLME through the target helper.

No SMMU, device, GIC, or TPM state changes occur. UNPROTECT only updates the
modeled service state. CLOSE_LOCALITY and ENABLE_SECURE_INTERRUPTS likewise
model the firmware-visible state and return values without cross-connecting
hardware.

## Optional vTPM phase

After the basic workflow passes, an optional device link may connect the DRTM
object to `tpm-tis-device`/`TPMBackend`. Keep it narrow:

- serialize internal commands with guest TPM traffic;
- model/acquire DRTM TPM localities;
- reset/extend the intended virtual PCRs using the software digest list; and
- optionally support `TPM2_PCR_Event` as a separate feature.

The vTPM link improves observable TPM fidelity but still does not create a
host security boundary. Failure can return a DRTM error in the test model.

## Optional strict hardware phase

Only after the basic workflow and optional vTPM work should separate patches
consider:

- authoritative virt memory/ACPI sources;
- a restricted DMA topology;
- an out-of-band SMMUv3 deny state;
- stopping/draining devices with retained DMA mappings;
- fw_cfg DMA handling; and
- GIC ITS/LPI quiescing.

Expose such work through a distinct strict mode, for example
`x-drtm-hw-protection=on`. It must not become a hidden prerequisite for
`x-drtm=on` or for the primary Drtm.efi workflow.

## Test strategy

Use three layers:

1. host unit tests for codecs, range checks, builders, and state transitions;
2. `tests/tcg/aarch64/system` payloads for SMC dispatch and CPU entry; and
3. selected/full `Drtm.efi` runs through `002-run-drtm-efi.sh`.

The basic milestone prioritizes interface and dynamic-launch tests. Record
tests which are skipped because they require real PCRs or hardware protection.
Do not block the basic workflow on later protection work.

## Non-goals of the basic milestone

- protection from malicious or concurrent virtual DMA devices;
- a secure measurement chain or production trust guarantee;
- faithful GIC/ITS or SMMU launch transitions;
- migration of DRTM state;
- DEN0113 v1.4B compliance; or
- replacing a real EL3 DRTM implementation.
