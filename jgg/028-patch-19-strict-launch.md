# Patch 19: wire optional strict protected launch

Proposed subject:

```text
hw/arm: Add strict DRTM protected launch
```

Wire patches 15-18 into the existing patch-9 workflow behind the separate
`x-drtm-hw-protection=on` option.

Changes:

- validate the strict topology and authoritative metadata before launch;
- stop/drain devices, quiesce GIC, and activate SMMUv3 protection before the
  strict measurement snapshot;
- use vTPM PCR operations if strict-mode policy requires them;
- implement post-boundary sticky-error/cold-reset remediation;
- restore guards/devices only through successful UNPROTECT;
- keep the original emulation-first transaction for `x-drtm=on` alone.

Failure-injection tests cover each boundary step, retained DMA writes, GIC,
SMMU, vTPM, remediation, unprotect, and repeat launch. Re-run Drtm.efi with
`DRTM_STRICT_HW=1` and independently inspect PCRs/guard behavior.

Acceptance: only this explicit mode makes a hardware-protection claim; it is
not part of the recommended patch-11 stop point.
