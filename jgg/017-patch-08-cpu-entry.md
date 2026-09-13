# Patch 8: add DRTM CPU entry state

Proposed subject:

```text
target/arm: Add DRTM firmware entry state
```

Add a focused helper for entering the current non-secure DLME.

Changes:

- derive the expected entry state from PSCI CPU_ON semantics plus the selected
  DRTM profile overrides;
- set AArch64 EL, endianness, SCTLR/PSTATE/DAIF state, X0, X1, and PC;
- preserve consistent architecturally UNKNOWN registers needed by the ACS
  DLME to restore its translation state;
- validate every fallible condition before mutation;
- rebuild hflags and force a TB exit/flush.

Boot-PE identity and secondary-PE checks remain board/service policy. Do not
use `arm_set_cpu_on()` for the already-running PE or a full `cpu_reset()`.

TCG tests seed registers and verify target EL, masks, MMU/cache state, X0/X1,
PC, retained state, and rejection of AArch32/bad EL/bad address.

Acceptance: the helper contains no virt, SMMU, GIC, or TPM policy.
