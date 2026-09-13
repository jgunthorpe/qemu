# Patch 11: add the Drtm.efi workflow test

Proposed subject:

```text
tests/functional: Exercise the Arm DRTM workflow
```

Turn the emulation-first milestone into a repeatable test without adding an
SMMU, restricted topology, or required TPM.

Changes:

- use a licensed/checksummed Drtm.efi asset pinned to a sysarch-acs revision;
- build a temporary pseudo-FAT directory with CRLF `startup.nsh`;
- boot QEMU-built EDK2 using TCG, `-cpu max`, four PEs, GICv3, and
  `x-drtm=on`;
- use ordinary virtio-blk-pci with no IOMMU-specific feature;
- select the documented workflow test set and intentional skips;
- strip console controls and require the completion marker, nonzero total, and
  zero failures for the selected set;
- preserve the QEMU command and console output on failure.

If binary redistribution is not ready, initially keep this as a developer-only
test using `DRTM_EFI`, while `jgg/002-run-drtm-efi.sh` remains the canonical
manual invocation.

Tests force ACS, QEMU, firmware, timeout, summary, and cleanup failures.

Acceptance: this patch is the recommended project stop point. The test proves
a DRTM SMC/DLME workflow, not virtual-hardware protection.
