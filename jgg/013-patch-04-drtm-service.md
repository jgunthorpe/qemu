# Patch 4: add the virt DRTM service

Proposed subject:

```text
hw/arm: Add the virt DRTM service
```

Introduce the machine option, QOM state, discovery calls, and modeled
non-launch state without any virtual-hardware cross-connect.

Changes:

- add a non-MMIO object under `VirtMachineState` and `hw/arm/meson.build`;
- add experimental `x-drtm=on`, restricted to TCG/AArch64/`secure=off` and the
  SMC conduit, with no SMMU/GIC/TPM requirement;
- register the exact DRTM FIDs on all initial CPUs;
- report VERSION 1.1 and implement FEATURES encoding for recognized feature
  and function queries;
- add idle/protected/locality/error fields and a migration blocker;
- return NOT_SUPPORTED for DYNAMIC_LAUNCH and optional calls not yet landed;
- add trace events explicitly labeling this as workflow emulation.

The DMA feature value may be prepared as a modeled workflow capability, but
documentation and traces must say it is not enforced. TPM-based hashing stays
clear and no TPM object link exists.

Tests cover option acceptance, default-off behavior, VERSION, feature query
encodings, invalid/reserved FIDs, reset, and PSCI regression. Run Drtm.efi
interface tests which do not require a working launch.

Acceptance: enabling the service changes only SMC-visible software state.
