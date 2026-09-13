# Patch 6: build workflow launch data

Proposed subject:

```text
hw/arm: Build DRTM launch data
```

Build the revision-1 DLME data layout needed by the ACS without claiming that
its protection metadata is enforced.

Changes:

- add a bounded host-side writer for header and aligned sections;
- emit the complete-protection sentinel as modeled metadata;
- emit a sorted/coalesced address map from configured virt RAM/platform ranges;
- reserve the event-log section used by patch 7;
- copy or describe guest-visible ACPI/TCB test data sufficiently for the ACS,
  labeling it untrusted workflow metadata;
- precompute total size and perform a single checked guest write later.

Tests independently parse generated buffers and cover exact-fit/short space,
count/offset overflow, stable ordering, RAM holes, descriptor values, and ACPI
table/checksum parsing where included. DYNAMIC_LAUNCH still does not enter the
DLME.

Acceptance: output is deterministic and structurally faithful; no SMMU, GIC,
TPM, fw_cfg, or device callback is introduced.
