# Post-review of the revised ARM DRTM plan

## Assessment

**Conditionally ready, but not yet implementation-ready.** The re-cut fixes
the original plan's central contract errors and is a much stronger basis for
work. Two acknowledged feasibility gates and two newly exposed implementation
details remain no-go conditions for publishing VERSION or successful launch.

The revised runner and its self-test pass `bash -n`; `006-test-runner.sh` also
passes end to end on this host.

## Disposition of the original findings

| Finding | Planning-level status |
|---|---|
| C1: both hash modes require TPM | **Partly resolved.** Real firmware/PCR work now precedes launch and PCR_Event is correctly optional, but the mandatory locality lifecycle is incomplete. |
| C2: measurement TOCTOU/phase boundary | **Resolved.** Measurement follows the all-quiet boundary and post-boundary failures remediate instead of returning. |
| C3: SMMUv3 is incomplete | **Partly resolved.** fw_cfg, virtio-mmio, GIC and topology are addressed, but already-mapped/in-flight SMMU-backed DMA is not explicitly drained. |
| C4: VERSION published too early | **Resolved.** The dormant service returns NOT_SUPPORTED until patch 15. |
| M1: callback from `pre_smc` | **Resolved.** Matching is immutable target-owned data; device code runs later under BQL. |
| M2: split 1.1/1.4 contract | **Open by design.** `005` correctly makes the missing DEN0113 1.1 audit a hard gate. |
| M3: TCB semantics | **Resolved.** Append, duplicates, capacity, X1 and repeat-lock behavior are now covered. |
| M4: patch width | **Mostly resolved.** Providers and guards are separated; patch 15 still carries too many state machines. |
| M5: CPU policy layering | **Resolved.** Machine policy and architectural state are separated. |
| M6: runner verdict | **Mostly resolved.** ACS summary parsing and failure artifacts work; final-profile TPM and pipeline/signal cases remain. |

## Remaining blockers and corrections

### Critical: complete the TPM locality contract

Affected: `001`, `005`, `020`, `021`, `024`.

The plans mention locality 4 and 3, but not the full mandatory handoff: open
localities 1, 2 and 3 for a launch, use/close locality 3 at the appropriate DCE
boundary, and enter the DLME with locality 2 active. CLOSE_LOCALITY must also
distinguish closed from not-yet-relinquished state in the real TPM frontend.
Add these transitions and reset/relaunch tests to patches 11-12 before freezing
patch 15. The existing HASH_START/HASH_DATA/HASH_END feasibility stop remains
a genuine critical gate, not merely a test detail.

### Critical: drain SMMU-backed devices, not only direct writers

Affected: `001`, `018`, `019`, `024`.

An IOMMU invalidation does not necessarily revoke a host pointer already
returned by `dma_memory_map()`. For example, virtio-blk may retain mapped guest
iovecs while block AIO is in flight. Patch 10's coordinator is described for
direct writers, but the irreversible boundary must first stop submissions and
drain every allowlisted DMA master, including PCI devices behind SMMUv3, then
activate/invalidate the guard. It must also account for queued ioeventfd work.
Add explicit in-flight virtio-blk and persistent ring-cache tests; otherwise a
pre-boundary request can write the measured region after the snapshot.

### Critical: close the version-profile gate

Affected: `005`, `023`, `024`.

The plan correctly refuses to guess, but it is still blocked until DEN0113 1.1
is obtained and the function-state, return-priority, locality and event tables
are completed. If that source cannot be obtained, switch to v1.4B and update
the ACS as `005` specifies. Do not begin guest-visible ABI implementation from
the candidate ACS behavior alone.

### Major: reduce patch 15 further

Affected: `003`, `016`, `024`.

Patch 15 still combines the launch coordinator, remediation, discovery
publication, UNPROTECT, both error calls, CLOSE_LOCALITY and profile-dependent
interrupt behavior. Add a pre-publication patch implementing and unit-testing
the internal mandatory state machines while every guest call still returns
NOT_SUPPORTED. Leave patch 15 as transaction wiring plus the atomic
VERSION/FEATURES exposure.

### Major: make the local runner's TPM requirement explicit

Affected: `002`, `004`, `006`.

The final profile requires a realized TPM2 device, but
`DRTM_SWTPM_SOCKET` is described as optional. With DRTM enabled, the runner's
otherwise-default invocation will therefore be rejected by the planned
machine profile. Either require the socket when `DRTM_ENABLE=1`, or add a
clearly bounded mode which launches and cleans up a private swtpm. Extend the
self-test to verify TPM argument construction.

Also capture both pipeline statuses: the runner currently records only
`PIPESTATUS[0]`, so a failed `tee` can be ignored. Add ANSI/CR, empty-summary,
zero-total and explicit HUP/INT/TERM cleanup cases; `031` currently overstates
the self-test's signal coverage.

### Major: make post-boundary serialization non-fallible or remediate

Affected: `022`, `023`, `024`.

Patch 14 says event-log serialization can “fail before launch,” but patch 15
obtains the actual successful PCR sequence only after crossing the boundary.
Prevalidate an exact or conservative size and all static encoding constraints
before the boundary, then make final serialization allocation-free. Any
remaining serialization/write failure after PCR activity must take the same
sticky-error cold-remediation path; it cannot be returned as an ordinary
launch failure.

## Final recommendation

Proceed with non-ABI groundwork—SMCCC, pure codecs, memory/ACPI providers and
focused guard prototypes—while the 1.1 and TPM feasibility gates are being
closed. Do not publish VERSION or claim an end-to-end DRTM launch until the
three critical items above have concrete designs and tests.
