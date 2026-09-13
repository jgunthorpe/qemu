# Remove launch-time ACPI TCB collection

## Decision

QEMU must not discover and hash ACPI tables during `DRTM_DYNAMIC_LAUNCH`.
The trustworthy TCB-hash path belongs to platform firmware: EDK2 must hash the
final TCB-critical tables while it is still executing under the platform
manufacturer's authority, submit them with `DRTM_SET_TCB_HASH`, and finish with
`DRTM_LOCK_TCB_HASHES` before End of DXE.

Changing EDK2 is outside the scope of this QEMU work.  Until that integration
exists, QEMU will permit a launch with no TCB hashes and will emit neither a
TCB-hash region nor an ACPI-table region in the DLME data.  This is an explicit
workflow-emulation deviation from DEN0113 v1.4B requirements R314070, R45420,
and R45440; it must not be described as providing trustworthy ACPI metadata.

The existing `DRTM_SET_TCB_HASH` and `DRTM_LOCK_TCB_HASHES` SMC interfaces stay
implemented.  If firmware does provide one or more hashes, QEMU will preserve
them and include them in the launch data.  A non-empty caller-provided set must
still be locked before launch, as required by R45290.  An empty set does not
require a lock operation.

## Proposed patch

```text
hw/arm: Remove DRTM launch-time ACPI hashing
```

This should be one reduction: remove the incorrect source of trust and make
the already-optional serialized TCB region genuinely optional.  Do not replace
the removed hashes with constants, zero digests, builder-template hashes, or
another QEMU-generated substitute.

## Implementation changes

### 1. Remove the platform ACPI collector

- Delete `hw/arm/virt-drtm-platform.c` and
  `hw/arm/virt-drtm-platform-internal.h`.
- Delete `include/hw/arm/virt-drtm-platform.h` if no non-collector declarations
  remain, and remove its includes.
- Remove `virt-drtm-platform.c` from `hw/arm/meson.build`.
- Remove `VirtDRTMPlatformTCB`, `VIRT_DRTM_PLATFORM_TCB_COUNT`, the five fixed
  ACPI IDs, and all collector status/error plumbing.
- Remove `platform_tcb` and `acpi_rsdp_address_le` from `VirtDRTMState`, along
  with their initialization and reset handling.

After this change, the DRTM service must have no code that reads an RSDP,
walks an XSDT, validates ACPI checksums, or hashes an installed ACPI table.

### 2. Remove the fw_cfg RSDP backchannel

- Remove `VIRT_DRTM_ACPI_RSDP_ADDR_FILE`.
- Remove the `bios_linker_loader_write_pointer()` operation that asks firmware
  to report the installed RSDP address to QEMU.
- Remove the corresponding `fw_cfg_add_file_callback()` registration in
  `virt_acpi_setup()`.

Normal Arm `virt` ACPI construction must be unchanged when DRTM is enabled or
disabled.  No DRTM-only fw_cfg file should remain.

### 3. Launch using only firmware-submitted hashes

In `virt_drtm_service_launch_with_ops()`:

- remove `VirtDRTMPlatformTCB`, `rsdp_address`, `platform_status`, and the call
  to `virt_drtm_platform_tcb_collect_acpi_full()`;
- set the launch hash count from `s->tcb_hashes.count` only;
- allocate the snapshot array only when the count is nonzero, so a valid empty
  set does not depend on the behavior of a zero-byte allocator;
- snapshot caller-provided hashes directly at the start of the array;
- pass `NULL, 0` to the DLME-data input when no hashes were recorded.

Keep the existing atomic launch behavior.  Removing ACPI collection also
removes ACPI parse, missing-table, checksum, allocation, and hash failures from
the returnable launch path.

### 4. Make the TCB-hash DLME region optional

Change `virt-drtm-data.c` so that `tcb_hash_count == 0` is valid:

- require `tcb_hashes != NULL` only when the count is nonzero;
- return a serialized TCB size of zero for an empty set;
- write zero to `DLME_DATA_HEADER.TCB hash table size` and emit no
  `TCB_HASH_TABLE` header or entries;
- do not call `write_tcb()` for the empty case;
- retain overflow, digest-size, ID source-bit, origin, and entry validation for
  every non-empty table;
- remove the hard-coded check that APIC, MCFG, GTDT, IORT, and TPM2 IDs must be
  present.  Firmware-submitted TCB entries may use any valid ID and duplicates
  remain permitted by the existing TCB store semantics.

The ACPI-table-region size remains zero.  Both optional region sizes are
therefore zero when EDK2 supplied no hashes.

### 5. Preserve SET/LOCK semantics

Do not remove or weaken the SMC codecs and state machine:

- `DRTM_FEATURES(TCB hash)` continues to advertise the real 64-entry
  caller-supplied capacity;
- `DRTM_SET_TCB_HASH` continues to validate and append atomically;
- `DRTM_LOCK_TCB_HASHES` continues to lock the accumulated set;
- a launch with zero entries is ready without a lock;
- a launch with one or more unlocked entries still enters the specified
  post-commit R45290 remediation path.

This distinguishes "firmware supplied nothing"—temporarily accepted for the
emulator—from "firmware supplied security-relevant data but failed to lock
it," which remains an error.

### 6. Correct feature sizing

In the minimum DLME-data page calculation, remove the five fixed platform TCB
entries.  Continue reserving worst-case space for the advertised 64
firmware-submitted entries.  Recheck boundary tests in case removing five
entries changes a page-count result for any active-bank combination.

## Tests

### Remove obsolete coverage

- Delete `tests/unit/test-virt-drtm-platform.c` and its Meson target.
- Remove synthetic RSDP/XSDT/table installation from the service-launch
  fixture.
- Remove the returnable platform-ACPI failure test and state-reset assertions
  concerning `platform_tcb`.

### Add or update coverage

- DLME data with `NULL, 0` TCB input succeeds, has TCB size zero, has ACPI size
  zero, and contains no bytes for either region.
- A non-empty locked firmware-supplied set is serialized exactly, with the
  `DRTM_SET_TCB_HASH` source bit set.
- Arbitrary valid IDs and duplicate IDs are accepted; absence of any of the
  five ACPI signatures is not rejected by QEMU.
- A non-empty unlocked set still remediates with TCB error ID `0x04`.
- A zero-entry unlocked store launches successfully.
- Launch success no longer depends on ACPI being enabled, on an installed
  RSDP, or on any particular ACPI table being present.
- Feature minimum-page tests use 64 possible caller entries rather than
  5 platform entries plus 64 caller entries.
- Interface tests for SET/LOCK behavior remain unchanged and continue to pass.

Run the affected unit suites and the Arm `virt` DRTM functional test.  Also
boot once with ACPI enabled and once with ACPI disabled, if the existing DRTM
machine prerequisites permit both configurations.

## ACS and conformance expectations

The checked-in Drtm.efi/ACS test for R45440 (test 117, "Check Trustworthy ACPI
Tables") is expected to fail until EDK2 performs the early SET/LOCK sequence
with hashes for MADT, MCFG, GTDT, IORT, and TPM2.  Any DLME-data test that
enforces R314070 may fail for the same reason.  Do not hide those results by
fabricating hashes in QEMU or by claiming that the reduced launch data is
DEN0113-conformant.

The runner and test map should distinguish:

- QEMU workflow/SMC tests, which remain expected to pass;
- ACPI-TCB conformance tests, which are an expected known failure while the
  required EDK2 work is out of scope.

Update `docs/system/arm/virt.rst` and `jgg/035-current-implementation.md` to
remove statements about fixed platform TCB records and launch-time hashes.
Document instead that QEMU serializes only hashes submitted through
`DRTM_SET_TCB_HASH`, permits the region to be absent for workflow emulation,
and therefore does not currently meet R314070/R45420/R45440 without cooperating
firmware.

## Acceptance criteria

- No DRTM code parses or hashes guest-visible ACPI tables.
- No DRTM-specific RSDP-address fw_cfg channel remains.
- A dynamic launch can succeed with zero TCB hashes and emits both optional
  region sizes as zero.
- Firmware-supplied, locked hashes are still included unchanged; supplied but
  unlocked hashes still trigger remediation.
- No QEMU validator requires the five ACPI signatures.
- Unit and workflow tests pass after removing obsolete platform-collector
  expectations.
- Documentation clearly records the temporary firmware-integration and
  DEN0113 conformance gap.

## Future EDK2 work (out of scope)

A separate firmware project must identify the finalized TCB-critical ACPI
tables, hash them with the algorithm advertised by `DRTM_FEATURES`, submit the
five R45440 entries through `DRTM_SET_TCB_HASH` while firmware is still in the
trusted pre-End-of-DXE phase, and call `DRTM_LOCK_TCB_HASHES` before extensible
components can run.  Once that exists, test 117 can return to the mandatory
passing set without restoring any ACPI parser in QEMU.
