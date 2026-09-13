# Patch 15: add authoritative platform metadata

Proposed subject:

```text
hw/arm: Add authoritative DRTM platform metadata
```

Begin the optional hardware-fidelity phase after the workflow already works.

Changes:

- export actual configured virt RAM, holes, and platform ranges through a
  board-owned iterator;
- expose exact finalized QEMU ACPI bytes before guest mutation;
- source MADT, MCFG, GTDT, IORT, and TPM2 from the builder when present;
- build relocated/checksummed ACPI or trustworthy TCB data;
- select this source only for the future strict mode; retain simple workflow
  metadata for ordinary `x-drtm=on`.

Tests compare provider data to configured memory and normal ACPI output,
including holes, checksums, TPM absent/present, and guest mutation.

Acceptance: this patch improves provenance without changing or blocking the
basic workflow.
