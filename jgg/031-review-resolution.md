# Resolution of the independent review

> Historical note: the security-first sequencing described here has been
> superseded for the basic workflow by `034-emulation-scope.md`. These
> resolutions now apply to the optional strict hardware phase.

`030-review.md` assessed the original 13-patch order as no-go. The plan was
then re-cut into the 18 reductions indexed by `003-patch-series.md`. This file
records dispositions without rewriting the independent review.

## Critical findings

| Finding | Resolution |
|---|---|
| C1: both hash modes need a TPM | A compatible TPM2 backend is now mandatory. Patches 11-12 land locality/transport and firmware digest/PCR work before launch. Patch 17 separately implements `TPM2_PCR_Event` and alone controls feature bit 32. Patch 11 is an explicit feasibility stop. |
| C2: pre-guard measurement TOCTOU | Patch 15 now does only structural/preallocation work before the boundary, then quiesces DMA/GIC before snapshotting any measured byte. Post-boundary failure retains guards and follows sticky-error/cold-reset remediation; it never unwinds into the old environment. |
| C3: SMMUv3 is incomplete | Patch 6 defines an allowlisted topology, disables fw_cfg DMA, requires zero virtio-mmio transports and modern virtio IOMMU use, and rejects hotplug/unapproved masters. Patch 9 is only the SMMU guard. Patch 10 separately drains ITS/direct writes and disables LPIs. The runner now uses non-transitional virtio with `iommu_platform=on`. |
| C4: early VERSION claim | Patch 7's dormant service returns NOT_SUPPORTED. Patch 15 atomically publishes VERSION, FEATURES, mandatory state calls, TPM measurement, guards, metadata, event log, and CPU entry. No earlier ACS-valid point is claimed. |

## Major findings

| Finding | Resolution |
|---|---|
| M1: callback from `pre_smc` | Patch 7 stores immutable conduit/FID metadata in ARMCPU. `pre_smc` matches target-owned data only; the device handler runs later under BQL. |
| M2: split compatibility contract | `005-compatibility-profile.md` pins both revisions, lists fixed choices and open decisions, records the candidate ACS event order, and makes DEN0113 1.1 acquisition a go/no-go gate. |
| M3: wrong TCB semantics | Patch 16 now specifies append across calls, permitted duplicate IDs, atomic per-call validation, X1 success/error details, source normalization, capacity, and DENIED on a second lock. |
| M4: patches too wide | The series grew from 13 to 18 patches. Codecs, memory, ACPI, topology, SMMU, direct/GIC DMA, TPM transport, PCR policy, launch data, event log, and final wiring are separate reductions. |
| M5: CPU policy layering | Patch 8 applies only architectural target state. Boot-PE/topology policy stays in patch 15's machine service under BQL, and required versus UNKNOWN register state is explicit. |
| M6: runner did not judge ACS | The runner now requires DRTM support by default, captures and cleans a log, checks completion/nonzero-total/zero-failures, propagates QEMU/timeout errors, and names the preserved log. `006-test-runner.sh` covers passing/failing summaries, missing support, baseline opt-out, timeout, paths with spaces, and QEMU failure. |

## Minor findings

- “non-world DCE” is corrected to “Normal-world DCE,” and the nonexistent
  standalone event-log address was removed from parameter alignment checks.
- The research scope now uses one explicit migration blocker rather than
  scattering partial migration implementation/tests across the series.
- The memory provider describes configured RAM/holes and rejects hotplug.
- TPM2 ACPI is mandatory for the final profile, not a fabricated/optional
  substitute.

## Current assessment

The planning structure is now conditionally ready for implementation, but two
pre-code gates remain genuine no-go conditions:

1. obtain/audit DEN0113 v1.1 or choose v1.4B and update ACS; and
2. prove QEMU's TPM abstraction can implement the mandatory firmware hashing
   and PCR sequence (including required PTP HASH semantics or an accepted
   equivalent).

These gates are deliberately not papered over by selected passing ACS tests.

The reviewer then performed a second pass in `032-post-review.md`; its
additional dispositions and the final 19-patch split are in
`033-post-review-resolution.md`.
