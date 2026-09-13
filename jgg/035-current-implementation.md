# Current Arm DRTM implementation contract

This document describes the current implementation.  It supersedes the
proposed compatibility profile and sequencing in `000` through
`028`.  Those files remain useful as the historical patch plan, but their
statements about DRTM 1.1, operation without a TPM, optional PCR updates, and
future SMMU/GIC enforcement do not describe the implemented `x-drtm` option.
The review records in `030` through `033` are intentionally archival.

## Published interface

`-machine virt,virtualization=on,secure=off,x-drtm=on` publishes the SMC64
firmware contract from DEN0113 version 1.4B.  It is available only for
AArch64 TCG guests with EL2, without CPU hotplug or migration.  QEMU handles
the DRTM calls alongside its PSCI provider and reports version 1.4 after the
frontend, routing, and locality-mediation prerequisites have initialized.

Exactly one `tpm-tis-device` frontend with a TPM 2.0 backend is required.
Machine initialization validates the frontend and TPM type and enables the
required locality mediation, but deliberately sends no TPM commands.  After
guest firmware has performed `TPM2_Startup`, the first metadata-dependent
feature, TCB-hash, or launch call discovers the active PCR banks and chooses a
supported firmware hash algorithm.  A transient discovery failure returns
`TPM_ERROR` and leaves the operation retryable; it does not terminate QEMU.
Launch hashes the DCE, DLME and configuration inputs in QEMU software.  The
D-CRTM stage sends `HASH_START`, `HASH_DATA`, and `HASH_END` to the TPM to
reset the dynamic PCRs and extend the DCE digest into PCR 17; later D-CRTM and
DCE measurements use `TPM2_PCR_Extend`.  QEMU emits the DEN0113 v1.4B
crypto-agile event log from the same manifest.  The profile never uses
`TPM2_PCR_Event`, so the TPM-based-hashing feature bit is clear.

## Guest-visible modeled state

Complete DMA protection, locality transitions, and secure-interrupt
disable/enable transitions are guest-visible service state.  Region protection
is not advertised: the launch feature and protection table are rejected, and
the maximum protected-region count is zero.  Complete protection implements
the specified ABI, validation, launch-data description, and error behavior.
It does not stop virtual DMA, reprogram an SMMU, quiesce the GIC/ITS, or create
a hidden host security boundary.  An SMMU and a restricted device topology are
therefore not prerequisites for `x-drtm=on`.

The service snapshots at most 4096 address-map descriptors.  That capacity is
included in the minimum DLME-data page count returned by `DRTM_FEATURES`; the
value is calculated from the active banks and worst-case emitted tables, not
hard-coded to one page.  Caller-provided TCB hashes have a separate 64-entry
capacity and are the only hashes serialized at launch.  A non-empty set must
be locked; a zero-entry store launches without a TCB-hash region.  QEMU emits
neither a TCB-hash region nor an ACPI-table region when firmware submits no
hashes.

QEMU does not discover or hash installed ACPI tables during launch.  Allowing
an empty set is an explicit workflow-emulation deviation from DEN0113 v1.4B
R314070, R45420, and R45440.  Meeting those requirements needs cooperating
firmware to hash the finalized TCB-critical tables, submit them through
`DRTM_SET_TCB_HASH`, and lock the set before End of DXE.

## Drtm.efi diagnostic

The checked-in `jgg/Drtm.efi` is the sysarch-acs v0.7-era binary and expects
the older DRTM 1.1 profile, including measurement details which differ from
DEN0113 v1.4B.  It is a useful boot and ABI diagnostic, but it is not an
oracle.  DEN0113 v1.4B wins whenever the two disagree, and the implementation
must not acquire compatibility branches or test-specific measurement ordering
solely to make this binary pass.

`jgg/002-run-drtm-efi.sh` keeps every run under `jgg/results/runs` (or another
in-repository `DRTM_RUN_ROOT`) and preserves the generated media, TPM state,
and console logs.  In the development sandbox, a live run can still be
blocked when QEMU or swtpm cannot create an AF_UNIX socket; that environment
restriction is not evidence of an implementation failure.  Generated run
directories are diagnostic artifacts and are not part of this source change.
