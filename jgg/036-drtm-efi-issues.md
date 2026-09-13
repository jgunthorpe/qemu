# Drtm.efi issues to fix

This document tracks defects exposed by the Arm DRTM Architecture Compliance
Suite (ACS) v0.7 `Drtm.efi` on QEMU `virt`. The reference contract is Arm
DEN0113 DRTM 1.4B (`jgg/DEN0113_DRTM_1.4B.pdf`); ACS source references are
relative to `../sysarch-acs`.

A valid fix must test or implement the DEN0113 software contract. Do not weaken
QEMU validation, special-case the ACS image, or change expected results merely
to make the suite pass. GIC isolation is out of scope for this emulation goal.

## Current result

`jgg/results/runs/run.9E9MhqRZ/console.log` is the current dynamic-launch run:

- 19 tests run: 12 passed, 4 failed, and 3 skipped;
- failures: 107, 113, 116, and 117;
- expected profile skips: 111 for complete DMA protection, and 112/115 because
  DLME image authentication is not advertised; and
- all other dynamic-launch tests, including event-log test 106 and successive
  launch test 103, pass.

The remaining failures are independent; the earlier TPM-locality cascade no
longer masks later tests.

## Priority 1: correct ACS default-schema ordering (test 113)

**Effort:** trivial, localized ACS test correction.

Test 113 reports `PCR[18] DLME not found or out of order`. The implementation's
order is correct; the checker in `test_pool/drtm/dl013.c` is not. DEN0113
R48020 and Table 40 require PCR[18] events in this order:

1. `EVTYPE_ARM_PCR_SCHEMA`
2. `EVTYPE_ARM_DCE_PUBKEY`
3. `EVTYPE_ARM_DEBUG_CONFIG`
4. `EVTYPE_ARM_NONSECURE_CONFIG`
5. `EVTYPE_ARM_DLME`
6. `EVTYPE_ARM_DLME_ENTRY_POINT`
7. `EVTYPE_ARM_SEPARATOR`

The ACS currently expects DLME and its entry point before debug and lifecycle
state. Reorder the test's assertions to match Table 40, while retaining exact
membership and no-extra-events checks for PCR[17] and PCR[18]. Do not reorder
QEMU's conforming event log.

Test 115 is skipped on this target, but contains the analogous latent defect.
Its `test_pool/drtm/dl015.c` checker must follow R48030/Table 42: PCR schema,
DCE public key, debug state, lifecycle state, DLME public key, optional DLME
SVN, DLME entry point, then separator. Fix it with test 113 so an
image-authentication implementation is not diagnosed incorrectly later.

Validation:

```sh
jgg/002-run-drtm-efi.sh -v 1 -m 100 -t 113
```

## Priority 2: synchronize the secondary PE (test 107)

**Effort:** small ACS concurrency fix.

Test 107 expects `SECONDARY_PE_NOT_OFF (-10)` but receives success. In
`test_pool/drtm/dl007.c`, the primary calls `val_execute_on_pe()` and launches
immediately; the secondary can also leave after an independent timeout. The
test therefore does not establish that the secondary is still on when the SMC
is issued. R44020 applies only when that premise is true.

Add a `secondary_ready` handshake using the ACS synchronization and cache
maintenance primitives. The primary must wait with a diagnostic timeout before
launching; once ready, the secondary must remain active until the primary
publishes `dl_done`. Publish `dl_done` on every cleanup path, wait for the
secondary to exit, and reset both flags between runs. Do not make QEMU return
`-10` based on the selected test or timing.

Validation:

```sh
jgg/002-run-drtm-efi.sh -v 1 -m 100 -t 107
```

Repeated runs must show the ready handshake before the launch and consistently
return `-10`.

## Priority 3: validate the two-stage DCE measurement (test 116)

**Effort:** small ACS event-log correction with multi-bank crypto coverage.

`test_pool/drtm/dl016.c` compares the `EVTYPE_ARM_DCE` event digest directly
with `Hash(0x00)`. DEN0113 R44160 and section 4.8.2 define two hashing stages
when there is no distinct DCE image:

- `DCE_digest` is the selected firmware algorithm's `Hash(0x00)`; and
- only the special `EVTYPE_ARM_DCE` record contains each active bank's
  `Hash_bank(DCE_digest)`.

Its event data is one densely packed `TPMT_HA` containing the un-rehashed
`DCE_digest` and selected firmware algorithm. Validate that structure once,
independently of validating every active bank's event digest as
`Hash_bank(DCE_digest)`. In contrast, `EVTYPE_ARM_DCE_PUBKEY` uses the ordinary
firmware-hashing measurement: validate `Hash_selected(0x00)` in the advertised
selected bank and require empty event data. Unused-bank PCR caps are a separate
operation and must not be mistaken for either event.

Reuse the bounded, algorithm-aware helpers used by passing test 106. Validation
should cover SHA-256, SHA-384, SHA-512, and mixed active banks:

```sh
jgg/002-run-drtm-efi.sh -v 1 -m 100 -t 116
```

## Priority 4: integrate trustworthy ACPI hashes in firmware (test 117)

**Effort:** large cooperating-firmware integration.

Test 117 reports missing MADT, MCFG, GTDT, IORT, and TPM2 hashes. This is the
intentional conformance gap left after removing QEMU's launch-time ACPI table
collection. DEN0113 R41000/R41010/R41050 require trusted non-secure firmware
to submit relevant hashes before End of DXE and lock the collection. R45420 and
R45440 require the DCE to provide the resulting TCB hash table or table copies
to the DLME, including those five mandatory tables.

Implement a cooperating EDK2 component that, while still in the trusted
firmware phase, locates the final mandatory tables, hashes each with the
algorithm advertised by `DRTM_FEATURES`, calls `DRTM_SET_TCB_HASH`, and then
calls `DRTM_LOCK_TCB_HASHES` before End of DXE. Preserve the source-of-entry
metadata when QEMU serializes the locked entries into DLME data. Handle table
replacement/order explicitly so the submitted digest is for the table exposed
to the launched environment.

Do not restore launch-time ACPI discovery in QEMU. At launch time QEMU cannot
establish that mutable non-secure ACPI bytes are trustworthy, and accepting
them there would evade the SET/LOCK ownership contract.

Validation:

```sh
jgg/002-run-drtm-efi.sh -v 1 -m 100 -t 117
```

The current `dl017.c` checks identifiers and a source mask but does not prove
the digest content; dummy hashes can pass. First validate the table structure:
revision 1, reserved field zero, exactly the advertised hash algorithm, bounded
count/entry arithmetic, and exact total size of header plus
`count * (4 + digest_size)` before dereferencing entries, with no trailing
bytes. Then locate the final ACPI tables exposed to the launched environment,
recompute each full digest, and reject wrong or truncated values.

DEN0113 permits implementation-provided and `DRTM_SET_TCB_HASH` entries, and
R315050 permits duplicate IDs. A generic ACS must accept either source, validate
claimed provenance where it is knowable, evaluate every duplicate, and require
at least one correct, unambiguous table association and digest for each actual
mandatory table. For this EDK2/QEMU provisioning route specifically, the five
entries are expected to claim the `DRTM_SET_TCB_HASH` source. Do not impose a
generic single-entry rule or accept an arbitrary duplicate that merely matches
an identifier.

## Non-failing cleanup debt

### Require the exact DEN0113 version under test

Interface test 1 currently passes, but the modified ACS accepts minor versions
1 through 4. A 1.4B test binary should require major 1, minor 4, or select an
explicit version-specific expectation set before running other tests. Report
both fields on mismatch; accepting an older contract while applying 1.4B
requirements can produce false results.

### Replace target-specific TPM locality hacks with owned transport flow

The current ACS contains hard-coded QEMU FIFO/TIS writes at `0x0c000000` and
`0x0c002000`, including an explicitly labelled `QEMU-only test hack`. They
make this target operational but are not a portable DCE/DLME ownership model:
they assume the interface and locality, do not discover resources, and do not
poll the resulting state.

Replace them with an owned, serialized TPM transport flow. Discover FIFO/TIS
or CRB resources from firmware description, acquire a locality only for a
transaction, relinquish it on every completion/error path, and verify no
locality is active immediately before each launch as required by R42120 and
R44060. The synthetic returning DLME must likewise relinquish locality 2
through that owned interface before control resumes as the next DCE preamble.
Unsupported transports should fail setup clearly, not fall back to QEMU MMIO
constants. See `jgg/037-arm-drtm-tpm-locality-boot-flow.md`.

## Resolved history

- QEMU now accepts the valid 19-byte TPM password-session success response to
  `TPM2_PCR_Extend`; test 102 reaches and completes dynamic launch.
- The operational locality-0/locality-2 lifecycle changes prevent one launch
  from contaminating the remainder of the suite; tests 102, 103, and 104 pass.
  The portable replacement remains cleanup debt above.
- The event-log parser and consumers are bounds-checked and
  algorithm/length-aware; test 106 passes with the current multi-bank log.
- ACS TCB hash-table tests use the advertised firmware hash algorithm and
  digest size; interface tests 13 and 14 pass.

Expected skips are not current defects: test 111 does not apply to complete DMA
protection, while tests 112 and 115 require unadvertised DLME image
authentication. The latent Table 42 error in test 115 is nevertheless included
in Priority 1. GIC blocking/isolation checks remain outside this project's
guest-visible software-contract scope.
