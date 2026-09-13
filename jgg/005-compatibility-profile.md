# DRTM workflow compatibility profile

> **Superseded profile.** This proposed ACS-oriented DRTM 1.1/no-TPM profile
> was rejected in favor of implementing DEN0113 v1.4B.  The active profile is
> documented in [035-current-implementation.md](035-current-implementation.md).
> The remainder of this file is archival and must not be used to justify
> compatibility shortcuts in the implementation.

## Purpose

The basic model targets the local Drtm.efi behavior rather than claiming full
DEN0113 conformance. This file records where the workflow profile intentionally
models architectural results without the corresponding protection mechanism.

Pinned inputs:

- QEMU base: `c7f5e06f580579`
- sysarch-acs: `f2c6c35450e7a9129cebe66f42de0136bf85e591`
- ACS-required VERSION: 1.1
- available design reference: DEN0113 v1.4B

## Basic profile

| Item | Workflow behavior |
|---|---|
| VERSION | 1.1 compatibility value |
| Call width | SMC64 FIDs `0xc4000110`-`0xc400011a` |
| Firmware digest | software SHA-256 (`0x000b`) |
| Event schema | default PCR schema, ACS-compatible order |
| TPM/PCR updates | none until optional phase 2 |
| TPM-based hashing bit | clear in basic mode |
| DMA protection feature | modeled complete-protection result; no enforcement |
| Protected-region table | complete-protection sentinel metadata |
| Localities | DRTM state-machine values; no TPM link |
| Secure interrupts | state/return/event emulation only |
| TCB SET/LOCK | patch 10 |
| Image authentication | not supported; conditional tests skip |
| Migration | blocked/out of scope |

The return-code enum remains 0 for success and -1 through -11 for the defined
failure classes used by the ACS. FEATURES distinguishes function queries from
feature-ID queries: implemented functions return X0=0; recognized feature IDs
return X0>0 and X1 even when the feature value is zero; unknown/reserved input
returns NOT_SUPPORTED.

## Event compatibility

Use the ordering expected by the pinned ACS for the basic profile:

- PCR 17 stream: DCE, PCR_SCHEMA, applicable optional records,
  SECURE_INTERRUPT_DISABLE when requested, then SEPARATOR.
- PCR 18 stream: PCR_SCHEMA, DCE_PUBLIC_KEY, DLME, DLME_ENTRY_POINT,
  DEBUG_CONFIGURATION, NON_SECURE_CONFIGURATION, then SEPARATOR.

These are modeled event streams until phase 2; the PCR numbers organize the
log but do not imply that a TPM was extended. Keep the non-distinct-DCE zero
digest behavior expected by ACS test 116.

## Optional vTPM profile

When `DRTM_SWTPM_SOCKET`/a TPM link is configured, patches 12-14 connect the
same workflow to virtual TPM commands and locality state. The service may then
advertise only the TPM capabilities it actually implements. The basic mode
must remain available without this link.

## Optional strict hardware profile

Patches 15-19 may add `x-drtm-hw-protection=on`. Only that mode may claim that
the modeled complete-protection state is backed by SMMU/GIC/device enforcement.
It may impose restricted topology and TPM requirements, but those restrictions
must not leak into the default workflow profile.

## Fidelity rule

SMC inputs, output registers, status codes, state transitions, parameter
layout, DLME handoff, and event bytes should be emulated faithfully. Hardware
side effects that are not implemented must be labeled modeled/no-op; they are
not blockers for the basic workflow.
