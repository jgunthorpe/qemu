# Patch 12: add optional vTPM transport

Proposed subject:

```text
tpm: Add internal DRTM command transport
```

Optionally connect the working DRTM service to QEMU's virtual TPM path. The
basic mode remains valid when no TPM is configured.

Changes:

- add a non-MMIO internal command interface on the TPM frontend;
- serialize DRTM commands with asynchronous guest requests;
- model/acquire/release DRTM TPM localities while keeping guest locality-4
  restrictions intact;
- validate command/response sizes, TPM return codes, timeout, and cleanup;
- make the DRTM object link optional at realization.

Tests use a mock backend for in-flight requests, locality conflicts, malformed
responses, timeouts, reset, and absence of a TPM. Add an swtpm transport smoke
test.

Acceptance: configuring a vTPM adds observable TPM behavior but no dependency
on SMMU, GIC, fw_cfg, or device topology.
