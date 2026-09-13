# Patch 13: mirror measurements into virtual PCRs

Proposed subject:

```text
tpm: Mirror DRTM measurements into virtual PCRs
```

Consume the software digest/event list from patch 7 and reproduce it in an
attached vTPM.

Changes:

- discover compatible active TPM2 banks;
- reset the selected dynamic PCRs and extend software SHA-256 digests in event
  order;
- implement the selected locality transitions around the command sequence;
- ensure the existing event log describes the successful virtual PCR updates;
- return modeled DRTM errors on backend failure without involving hardware
  protection or DMA remediation;
- update TPM FEATURES only when a compatible vTPM is realized.

Mock and swtpm tests cover bank selection, reset/extend order, locality state,
partial TPM failure, and an independent event-log replay to the same PCRs.
Re-run the Drtm.efi workflow with `DRTM_SWTPM_SOCKET`.

Acceptance: virtual PCRs agree with log replay; basic no-TPM launch is unchanged.
