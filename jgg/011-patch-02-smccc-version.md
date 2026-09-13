# Patch 2: report the emulated SMCCC version

Proposed subject:

```text
target/arm: Report the emulated SMCCC version
```

Make QEMU's existing in-process PSCI firmware path answer SMCCC_VERSION, an
ACS prerequisite independent of DRTM.

Changes:

- define/reuse the architectural function and version encodings;
- handle the call on the configured PSCI conduit while preserving registers;
- retain existing HVC/SMC routing and unknown-function behavior.

Tests use a TCG payload for both conduits, rerun PSCI version/unknown-FID
coverage, and run Drtm.efi interface tests 8 and 9.

Acceptance: the reported revision is backed by QEMU's implemented SMCCC
behavior and this patch contains no DRTM machine state.
