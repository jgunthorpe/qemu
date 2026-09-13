# ARM DRTM workflow emulation in QEMU

> **Superseded plan.** This was the initial 1.1/no-TPM implementation plan.
> The implemented DEN0113 v1.4B contract and current prerequisites are recorded
> in [035-current-implementation.md](035-current-implementation.md).  The text
> below is retained only as historical planning context.

## Goal

Implement enough of the Arm DRTM firmware interface in QEMU to execute and
test a complete DRTM SMC workflow inside an Arm `virt` VM. QEMU directly
handles the SMC calls; no Trusted Firmware-A, EL3 payload, or secure-world
guest is required.

The priority is interface and control-flow fidelity:

- dispatch the DRTM SMC FIDs correctly alongside QEMU's emulated PSCI;
- validate the DRTM parameter ABI and return the expected status codes;
- construct DLME data and an event log suitable for the local ACS;
- enter the supplied DLME with the expected CPU/register state;
- emulate locality, error, launch, and unprotect state transitions; and
- run the complete workflow through `Drtm.efi`.

The first implementation is intentionally a test model. “Protected” is a
guest-visible DRTM state, not a guarantee that QEMU has blocked every virtual
device from accessing RAM. SMMU, GIC/ITS, fw_cfg, and device-DMA enforcement
are explicitly outside the basic milestone.

## Test target

The System Architecture Compliance Suite source is:

```text
/home/jgg/oss/sysarch-acs/test_pool/drtm/
```

The local runner expects the built application at:

```text
/home/jgg/oss/sysarch-acs/workspace/output/Drtm.efi
```

The ACS currently checks DRTM version 1.1 even though the design reference in
this directory is DEN0113 v1.4B. The initial profile therefore follows the
pinned ACS behavior and is described as a compatibility/test profile, not a
claim of DEN0113 compliance.

## Repository and build

The plan was prepared for the QEMU tree descended from revision
`c7f5e06f580579`. The configured build directory is `build-arm/`:

```sh
ninja -C build-arm
```

The main executable and firmware image are:

```text
build-arm/qemu-system-aarch64
build-arm/pc-bios/edk2-aarch64-code.fd
```

## Basic machine interface

The workflow model uses an explicitly experimental option:

```text
-machine virt,virtualization=on,gic-version=3,x-drtm=on
```

It is TCG-only and requires `secure=off`, because QEMU is acting as the
firmware SMC provider in the absence of a modeled EL3. It does not require an
SMMU or TPM. A vTPM may be connected by the optional second phase.

## Implementation phases and stop point

The sequence is intentionally split by value to this project:

1. **Basic workflow, patches 1-11:** implement the SMC ABI, software
   measurements/event log, DLME handoff, state calls, and a Drtm.efi test.
   This is the primary deliverable and the recommended stopping point.
2. **Optional vTPM, patches 12-14:** connect the emulated DRTM service to
   QEMU's TPM frontend/backend and mirror measurements into PCRs.
3. **Optional hardware-fidelity work, patches 15-19:** improve authoritative
   metadata and add topology, SMMUv3, GIC/ITS, and direct-DMA enforcement.
   These patches are not prerequisites for a working DRTM workflow.

The reordered series is indexed by
[003-patch-series.md](003-patch-series.md). The detailed architecture is
[001-architecture-plan.md](001-architecture-plan.md), the test inventory is
[004-drtm-efi-test-map.md](004-drtm-efi-test-map.md), and the explicit
compatibility choices are [005-compatibility-profile.md](005-compatibility-profile.md).

The local test runner is [002-run-drtm-efi.sh](002-run-drtm-efi.sh), with
fake-QEMU regression coverage in [006-test-runner.sh](006-test-runner.sh).

## Definition of done for the basic milestone

- `x-drtm=on` registers a DRTM SMC provider without changing PSCI behavior.
- VERSION, FEATURES, mandatory calls, invalid inputs, and return registers
  match the documented 1.1 compatibility profile.
- A valid DYNAMIC_LAUNCH transfers control to the ACS DLME with X0/X1 and CPU
  state set as expected.
- The DLME can return to the ACS, call UNPROTECT/CLOSE_LOCALITY/error services,
  and perform another launch according to the state machine.
- Software SHA-256 measurements and the event log are deterministic and
  parseable by Drtm.efi; no TPM/PCR claim is made.
- The runner boots Drtm.efi from the bundled EDK2 shell and returns failure
  when the ACS summary reports failed tests.
- Each commit builds independently and follows QEMU commit style.

## Historical review context

The earlier security-oriented plan and its reviews are retained in
`030-review.md` through `033-post-review-resolution.md`. Their protection
concerns are valid for a security-capable DRTM model, but the current scope
deliberately moves those concerns to the final optional phase. The scope change
is recorded in [034-emulation-scope.md](034-emulation-scope.md).
