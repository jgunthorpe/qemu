# Emulation-first patch series

> **Superseded patch plan.** The implemented series no longer follows these
> phase boundaries: TPM2 locality/PCR operations became mandatory and the
> published ABI follows DEN0113 v1.4B.  See
> [035-current-implementation.md](035-current-implementation.md).  The proposed
> subjects and milestones below are retained to explain the series' origin.

The sequence is organized around an early working Drtm.efi milestone. The
first group contains no SMMU, GIC, fw_cfg-DMA, device-drain, or required-TPM
cross-connect. Stop after patch 11 if the project only needs a VM workflow.

## Phase 1: basic DRTM workflow — primary deliverable

| Patch | Proposed subject | Reduction |
|---:|---|---|
| 1 | `docs/system/arm: Document the virt DRTM workflow model` | Explicit non-security contract |
| 2 | `target/arm: Report the emulated SMCCC version` | ACS firmware prerequisite |
| 3 | `target/arm: Add firmware SMC provider dispatch` | DRTM/PSCI routing seam |
| 4 | `hw/arm: Add the virt DRTM service` | QOM object, discovery, basic state |
| 5 | `hw/arm: Decode DRTM launch parameters` | Guest ABI validation |
| 6 | `hw/arm: Build DRTM launch data` | DLME header/map/test metadata |
| 7 | `hw/arm: Build the DRTM software event log` | SHA-256 modeled measurements |
| 8 | `target/arm: Add DRTM firmware entry state` | CPU/DLME handoff |
| 9 | `hw/arm: Implement the DRTM workflow launch` | End-to-end state/launch calls |
| 10 | `hw/arm: Add mutable DRTM TCB hashes` | Remaining optional SMC fidelity |
| 11 | `tests/functional: Exercise the Arm DRTM workflow` | Drtm.efi milestone |

**Recommended stopping point: patch 11.** At this point the VM exercises
VERSION/FEATURES, parameter parsing, dynamic launch, DLME execution/return,
event data, locality/error calls, unprotect, repeat launch, and TCB calls. The
model makes no virtual-hardware protection claim.

Detailed plans:

- [010-patch-01-workflow-docs.md](010-patch-01-workflow-docs.md)
- [011-patch-02-smccc-version.md](011-patch-02-smccc-version.md)
- [012-patch-03-smc-dispatch.md](012-patch-03-smc-dispatch.md)
- [013-patch-04-drtm-service.md](013-patch-04-drtm-service.md)
- [014-patch-05-launch-parameters.md](014-patch-05-launch-parameters.md)
- [015-patch-06-launch-data.md](015-patch-06-launch-data.md)
- [016-patch-07-software-event-log.md](016-patch-07-software-event-log.md)
- [017-patch-08-cpu-entry.md](017-patch-08-cpu-entry.md)
- [018-patch-09-workflow-launch.md](018-patch-09-workflow-launch.md)
- [019-patch-10-tcb-hashes.md](019-patch-10-tcb-hashes.md)
- [020-patch-11-workflow-test.md](020-patch-11-workflow-test.md)

## Phase 2: optional vTPM fidelity

| Patch | Proposed subject | Reduction |
|---:|---|---|
| 12 | `tpm: Add internal DRTM command transport` | Serialize vTPM/locality access |
| 13 | `tpm: Mirror DRTM measurements into virtual PCRs` | PCR reset/extend workflow |
| 14 | `tpm: Add TPM2_PCR_Event support for Arm DRTM` | Optional TPM hashing mode |

These are the only near-term device cross-connects relevant to the stated
scope. They are optional: the basic workflow continues to work without a TPM.

- [021-patch-12-vtpm-transport.md](021-patch-12-vtpm-transport.md)
- [022-patch-13-vtpm-pcrs.md](022-patch-13-vtpm-pcrs.md)
- [023-patch-14-tpm-event-hashing.md](023-patch-14-tpm-event-hashing.md)

## Phase 3: optional hardware-protection fidelity

| Patch | Proposed subject | Reduction |
|---:|---|---|
| 15 | `hw/arm: Add authoritative DRTM platform metadata` | Trusted memory/ACPI source |
| 16 | `hw/arm: Add a strict virt DRTM topology` | Optional device allowlist |
| 17 | `hw/arm: Add a DRTM SMMUv3 DMA guard` | Optional IOMMU enforcement |
| 18 | `hw/arm: Quiesce DMA and GIC for DRTM launch` | Optional ITS/direct-device work |
| 19 | `hw/arm: Add strict DRTM protected launch` | Wire strict mode and tests |

Nothing in phase 3 is required by `x-drtm=on`. If implemented, expose it as a
separate opt-in strict mode so it cannot delay or destabilize the workflow
emulator.

- [024-patch-15-platform-metadata.md](024-patch-15-platform-metadata.md)
- [025-patch-16-strict-topology.md](025-patch-16-strict-topology.md)
- [026-patch-17-smmuv3-guard.md](026-patch-17-smmuv3-guard.md)
- [027-patch-18-dma-gic-quiesce.md](027-patch-18-dma-gic-quiesce.md)
- [028-patch-19-strict-launch.md](028-patch-19-strict-launch.md)

## Commit discipline

Every patch builds independently, uses a QEMU subsystem-prefixed imperative
subject, and states its expected Drtm.efi progress. Partial phase-1 commits may
return NOT_SUPPORTED for functionality not yet wired. Patch 9 is the first
complete workflow point; patch 11 turns it into a repeatable integration test.
