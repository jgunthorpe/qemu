# Patch 1: document the workflow model

Proposed subject:

```text
docs/system/arm: Document the virt DRTM workflow model
```

Define the experimental contract before code lands.

Changes:

- document `-machine virt,virtualization=on,x-drtm=on`;
- require TCG/AArch64 and `secure=off`, but not SMMU or TPM;
- state prominently that protected memory, DMA protection, TPM localities, and
  secure-interrupt changes are modeled state in the basic mode;
- document the 1.1 ACS compatibility target and SHA-256 software event log;
- describe unsupported migration and CPU hotplug;
- show the Drtm.efi runner command and selected-test syntax;
- reserve a separate future `x-drtm-hw-protection` strict mode.

Tests build the QEMU documentation and run checkpatch. This patch adds no
machine property or code.

Acceptance: a user cannot mistake the workflow emulator for a security or
DEN0113-compliance feature.
