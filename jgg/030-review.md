# Independent review of the ARM DRTM plan

## Assessment

**No-go for implementation in the proposed order.** The high-level choice to
dispatch a machine-owned DRTM service beside QEMU's emulated PSCI path is
reasonable. The series nevertheless has four release-blocking contract errors
and several patches are too broad to review safely. Resolve the critical items
below, then re-cut the sequence before writing production code.

This review used QEMU base revision `c7f5e06f580579`, sysarch-acs revision
`f2c6c35450e7a9129cebe66f42de0136bf85e591`, and the checked-in DEN0113 v1.4B.

## Critical findings

### C1. Both hashing modes require a real TPM

Affected: `000`, `001`, `003`, `016`, `019`, `021`.

The proposed patches 1-10 allow a successful "software-measurement MVP" and
defer real TPM work to patch 12. DEN0113 section 2.7.1 does not define
firmware-based hashing as a no-TPM mode: firmware computes a digest and extends
it into the TPM. Bit 32 clear in the TPM feature response distinguishes this
from `TPM2_PCR_Event`; it does not make PCR operations optional. The DCE
measurement also needs HASH_START/HASH_DATA/HASH_END or a justified equivalent,
and unused active PCR banks must be capped. An event log must describe the
measurements actually made into PCRs.

Move the minimum TPM frontend/backend work before successful dynamic launch.
Split it into (a) serialization/locality ownership, dynamic-PCR reset/DCE hash
sequence, bank discovery and firmware-based extends, and (b) optional
`TPM2_PCR_Event` support, which alone controls the TPM-based-hashing bit. Do a
feasibility spike first: `TPMBackend` currently transports TPM command buffers
but does not obviously expose the PTP HASH signals. Require a compatible TPM2
device/backend for `x-drtm=on`, and do not publish a valid DRTM version until
this mandatory path exists.

### C2. The launch ordering has a DMA time-of-check/time-of-use window

Affected: `001` dynamic-launch transaction, `014`, `016`, `019`.

The plan hashes and builds metadata from guest RAM before activating the DMA
guard. An asynchronous device can change the DLME image or referenced data
after it is validated/measured but before entry, so the executed image need not
match its measurement. Copying only `DRTM_PARAMETERS` once does not close this
window.

Keep only returnable, side-effect-free structural checks in phase 1. At the
irreversible boundary, block and drain DMA (and quiesce the GIC as in C3), then
read/snapshot the measured inputs, reset/extend PCRs, write metadata, and enter
the DLME. Preallocate enough state that this path is as close to infallible as
possible. If a phase-2 operation fails, DEN0113 requires sticky-error
remediation and a cold reset; the plans' proposed guard rollback and normal
return after state has changed is not conforming.

### C3. SMMUv3 translation denial alone is not complete DMA protection

Affected: `001`, `010`, `018`, `019`, `022`; runner topology.

`virt` always creates DMA-capable fw_cfg with `fw_cfg_init_mem_dma()` against a
direct address space. The GIC ITS and redistributors can also write guest RAM
without traversing the SMMUv3; DEN0113 R44080 specifically requires disabling
and quiescing every ITS and disabling LPIs. Arbitrary sysbus devices, populated
virtio-mmio transports, hotplugged devices, and PCI devices that deliberately
select `address_space_memory` remain additional concerns. A late object-tree
scan cannot generally prove that an arbitrary QEMU device never performs DMA.

Define an enforceable restricted machine profile: disable fw_cfg DMA (or add a
separate guard), set `virtio-mmio-transports=0`, prohibit device/CPU/memory
hotplug and unapproved dynamic sysbus devices, and allowlist DMA masters whose
actual DMA `AddressSpace` is guarded. Add a separate GIC ITS/LPI quiesce patch
and test its ordering. The current runner's
`virtio-blk-pci-non-transitional,iommu_platform=on` is the correct improvement;
without `iommu_platform`, virtio uses `address_space_memory` even on an
SMMU-attached PCI bus. Make these restrictions concrete rather than an audit
item inside the already-large SMMUv3 patch.

### C4. Patch 4 advertises a valid version before mandatory behavior exists

Affected: `001`, `003`, `013`, `019`.

Patch 4 reports VERSION 1.1 while `DYNAMIC_LAUNCH` deliberately remains
unavailable, and later patches defer other state semantics. A valid VERSION
means the mandatory functions for that revision are implemented. This
contradicts both feature-advertisement honesty and the proposed claim that every
intermediate commit is usable.

Build parsers, builders, guards and state behind internal tests first. Until
the end-to-end commit, either leave the machine property absent or make VERSION
return NOT_SUPPORTED and clearly expect ACS interface test 1 to fail. Publish
VERSION and mandatory function discovery atomically with successful launch.
Use one hard-coded compatibility profile, not a configurable version number
whose behavior is otherwise unchanged.

## Major findings

### M1. The SMC match callback is too powerful for `pre_smc`

Affected: `001`, `011`.

`HELPER(pre_smc)` runs in translated vCPU execution before the later BQL
assertion in `arm_cpu_do_interrupt()`. Calling arbitrary board/device callbacks
there creates locking, lifetime, and reentrancy hazards. Store an immutable
conduit plus exact FID range/bitmap in `ARMCPU` and let target code perform the
side-effect-free match itself; invoke only the handler from the exception path
under the BQL. Also document caller EL/security checks and provider lifetime.

Patch 2's proposed TCG guest cannot install a host-side dummy provider without
test-only machine plumbing. Prefer unit-testing the registry/matcher and land
the first real provider with the dispatch seam, or explain why the otherwise
unused generic API is acceptable.

### M2. The compatibility contract is under-specified and internally split

Affected: `000`, `001`, `003`, `016`, `022`.

The local ACS hard-codes VERSION 1.1 but contains newer tests. Its PCR[18]
ordering in `dl013.c` places DLME and entry-point events before debug and
lifecycle events, whereas v1.4B reordered those measurements. SHA-256 and the
zero-DCE checks add more local assumptions. Pin the ACS revision in the plan
and add an explicit profile matrix for return codes, feature fields, event
order/digest semantics, secure-interrupt behavior, and intentional skips.
Do not alternate between "DEN0113 order" and whatever makes this ACS green.

### M3. Optional TCB-hash semantics are wrong

Affected: `020`.

`DRTM_SET_TCB_HASH` calls accumulate a single list; they do not replace the
entire prior set. Duplicate IDs are expressly permitted by R315050. On success
X1 reports the number of valid entries populated, and on INVALID_DATA it
identifies the bad entry. Re-lock returns DENIED, not an idempotent success.
Rewrite the state-machine plan and tests around append-with-atomic-validation,
capacity across calls, permitted duplicates, supplemental X1, source-bit
normalization, and exact reset persistence.

### M4. Several planned commits are much wider than one reviewable reduction

Affected: `013`, `015`, `018`, `019`, `021`.

Patch 6 combines a bounded wire builder, a complete virt address-map model,
an ACPI-builder API, ACPI relocation/XSDT repair, and trust policy. Patch 9
combines SMMU enforcement, invalidation, migration/reset, machine topology
proof and hotplug policy. Patch 12 combines concurrency, localities, TPM wire
protocol, PCR policy, migration and ACPI. Split those concerns. In particular,
separate pure ABI codecs, virt memory-map export, ACPI provenance, SMMUv3
guard, topology restrictions, GIC quiesce, TPM transport/localities, and PCR
policy. Patch 10 should then be small wiring over independently exercised
pieces.

### M5. CPU policy is in the wrong layer

Affected: `017`.

The target/arm entry helper should not decide whether a CPU is the virt board's
boot PE. Boot-PE identity, secondary-PE power checks, topology races and the
requested profile belong to the machine-owned DRTM service under the BQL. The
target helper should only validate and apply architectural CPU state. Derive
that state explicitly from PSCI CPU_ON plus DEN0113 overrides, including which
registers are UNKNOWN versus required; retaining TTBR/TCR/MAIR for the ACS may
be a valid UNKNOWN choice but must not be presented as a DEN0113 requirement.

### M6. The local runner launches ACS but does not report its result

Affected: `002`, `000` definition of done.

Syntax and baseline boot were verified. The read-only bundled EDK2 image finds
the pseudo-FAT disk, and the updated non-transitional virtio device with
`iommu_platform=on` works. However, `Drtm.efi` returns EFI success even when
its internal summary reports failed tests, so QEMU exits zero after `reset -s`
and this script also exits zero. Conversely, the shell aborts `startup.nsh` on
an EFI application error, never reaches `reset -s`, and the run merely times
out. The default also silently falls back to a no-DRTM baseline when the
machine property is absent.

Capture console output unconditionally, strip CR/ANSI for parsing, require the
completion marker, a nonzero total, and `Tests Failed = 0`, and return nonzero
otherwise. Make missing DRTM support fatal by default; retain an explicit
baseline mode. Include the printed command in the saved log, and preserve or
name the log on failure. Add self-tests with a fake QEMU executable for option
detection, timeout, signal cleanup, spaces in paths, and summary parsing.

## Minor findings

- `001` says “non-world DCE”; this should be “Normal world DCE.” Its validation
  list also mentions an event address even though event-log storage is a DLME
  data section, not a `DRTM_PARAMETERS` address field.
- The ungrammatical bold NOTE in `001` conflicts with repeated migration work.
  If migration is out of scope, install a migration blocker in the first
  stateful patch and remove migration implementation/tests from this series.
- `015` must describe actual configured RAM, holes, hotplug policy and MMIO,
  not merely static `vms->memmap` slots. Required ACPI trust data is not an
  optional capability: a missing TPM2 table is another reason not to allow a
  successful launch before TPM integration.

## Recommended re-cut

Keep documentation first as QEMU requests, but describe a final contract.
Then land: SMCCC prerequisite; pure DRTM codecs/parsers; virt memory/ACPI
providers; restricted-topology policy; SMC dispatch plus dormant service;
architectural CPU entry; SMMUv3 guard; fw_cfg/GIC quiesce; TPM
transport/locality and mandatory firmware-based PCR measurements; launch-data
and event builders; finally the atomic dynamic-launch commit which exposes
VERSION/FEATURES. Follow with optional TCB mutation, optional TPM-based hashing,
and the licensed ACS functional test.

After C1-C4 and the runner result handling are corrected, the project is a
credible implementation plan. Until then, passing selected ACS layout tests
would demonstrate an emulator shim, not the DRTM contract the plans claim.
