# Patch 3: add firmware-SMC provider dispatch

Proposed subject:

```text
target/arm: Add firmware SMC provider dispatch
```

Create the generic routing seam beside QEMU's fake PSCI handling.

Changes:

- store immutable conduit plus exact FID range/bitmap metadata in ARMCPU;
- let `HELPER(pre_smc)` match that target-owned data without a device callback;
- invoke a registered handler from `arm_cpu_do_interrupt()` under the BQL,
  before the PSCI fallback;
- define registration lifetime, overlap rejection, CPU setup, caller
  EL/security checks, and common plugin-hostcall completion;
- preserve architectural delivery when neither provider nor PSCI handles a
  call and preserve real-EL3 behavior.

Tests cover range edges, wrong conduit, provider overlap, PSCI priority,
unknown calls, real EL3, and callback lifetime. A minimal test provider may be
used until patch 4 registers DRTM.

Acceptance: `target/arm` has no dependency on the virt board or DRTM types.
