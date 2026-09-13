# Drtm.efi workflow test map

This inventory comes from sysarch-acs revision
`f2c6c35450e7a9129cebe66f42de0136bf85e591`. The runner uses the checked-in
`jgg/Drtm.efi` by default. That v0.7-era application expects DRTM 1.1 and is a
diagnostic target only; DEN0113 v1.4B remains authoritative when its
expectations differ.  The planned-patch references below are historical; see
[035-current-implementation.md](035-current-implementation.md) for the
implemented contract.

## Runner examples

```sh
# Basic emulation workflow; starts an installed swtpm automatically
jgg/002-run-drtm-efi.sh -v 1 -t 1,2,3,8,9,101,102,103,104

# All interface tests or all dynamic-launch tests
jgg/002-run-drtm-efi.sh -v 1 -m 0
jgg/002-run-drtm-efi.sh -v 1 -m 100

# Use an already-running TPM2 swtpm instead of automatic startup
DRTM_SWTPM_SOCKET=jgg/results/external-swtpm/control.sock \
    jgg/002-run-drtm-efi.sh -v 1

# Optional SMMUv3-oriented runner topology; this does not enable enforcement
DRTM_STRICT_HW=1 jgg/002-run-drtm-efi.sh -v 1
```

Missing QEMU DRTM support is fatal by default. Use `DRTM_ENABLE=0` only for an
explicit baseline firmware/application boot.

Each invocation preserves its EFI media, raw and cleaned console output, QEMU
scratch files, and automatic swtpm state beneath `jgg/results/runs`. Set
`DRTM_RUN_ROOT` to select another directory within the repository. No runner
cleanup deletes diagnostic artifacts. An explicit `DRTM_SWTPM_SOCKET` is
canonicalized and must also name a path inside the repository; this keeps all
runner-controlled paths within the checkout even when using an existing TPM.

Drtm.efi prints a summary but returns EFI success even on internal failures.
The runner therefore requires the completion marker, a nonzero total, and
zero failed tests.

## Interface tests

| ID | Description | First planned patch |
|---:|---|---:|
| 1 | DRTM version | 4/9 |
| 2 | Invalid/reserved FIDs | 4 |
| 3 | Mandatory function discovery | 9 |
| 4 | TCB feature reserved bits | 4 |
| 5 | DMA feature encoding | 4/9, modeled only |
| 6 | TPM feature encoding | 4/9, modeled; real vTPM in 13 |
| 7 | Minimum memory feature | 4 |
| 8 | PSCI version | existing QEMU |
| 9 | SMCCC version | 2 |
| 10 | GIC supports disabling LPIs | existing model/prerequisite |
| 11 | GICR_PENDBASER behavior | existing model/prerequisite |
| 12 | LOCK_TCB_HASHES | 10 |
| 13 | Maximum SET_TCB_HASHES | 10 |
| 14 | Invalid/locked TCB hashes | 10 |
| 15 | Image-auth feature reserved bits | 4; value zero |

## Dynamic-launch tests

| ID | Description | First planned patch |
|---:|---|---:|
| 101 | Invalid launch parameters | 5/9 |
| 102 | Successful launch/X0/X1/unprotect | 9 |
| 103 | Repeated launch denied until unprotect | 9 |
| 104 | Locality state | 9 |
| 105 | DLME data rules | 6/9 |
| 106 | Event-log format | 7/9 |
| 107 | Secondary PE on | 9 |
| 108 | Invalid launch features | 5/9 |
| 109 | Authority schema without image auth | 9 |
| 110 | Launch from a non-boot PE | 9 |
| 111 | Memory-region descriptors | 6/9, modeled protection |
| 112 | DLME image authentication | intentionally skipped |
| 113 | Default event ordering | 7/9 |
| 114 | Non-secure exception masks | 8/9 |
| 115 | Authority event ordering | intentionally skipped |
| 116 | Zero digest for non-distinct DCE | 7/9 |
| 117 | ACPI test metadata | 6/9; authoritative source in 15 |
| 118 | Debug exception mask | 8/9 |
| 119 | Secure-interrupt command | 9, state emulation only |

Passing tests 5, 111, or 119 in workflow mode verifies ABI/metadata behavior,
not real DMA, memory, or GIC enforcement. The console log and documentation
must retain that distinction.

## Milestones

- Patch 4: raw VERSION/FEATURES/FID routing can be selected directly.
- Patch 5: invalid parameter cases can run; launch still returns unsupported.
- Patches 6-8: builders and CPU entry are exercised by focused unit/TCG tests.
- Patch 9: run the interface suite plus applicable dynamic tests.
- Patch 10: add interface tests 12-14.
- Patch 11: run the stable workflow subset automatically.
- Patches 12-14: additionally inspect virtual PCRs/event-log replay.
- Patches 15-19: re-run under optional strict hardware mode.
