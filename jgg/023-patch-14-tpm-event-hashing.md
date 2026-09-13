# Patch 14: add optional TPM-based hashing

Proposed subject:

```text
tpm: Add TPM2_PCR_Event support for Arm DRTM
```

Add the alternate mode in which the configured vTPM performs hashing through
`TPM2_PCR_Event`.

Changes:

- add checked PCR_Event transport over the copied launch inputs;
- validate backend support, response algorithms/digests, active banks, and
  command size;
- construct event records from successful TPM responses;
- expose the TPM-based-hashing feature bit only for this mode;
- retain software digest/extend and no-TPM workflow modes as fallbacks.

Tests cover feature absence, malformed/multi-bank responses, size limits,
PCR/log agreement, and all three modes.

Acceptance: the advertised bit reflects real vTPM hashing, while remaining a
virtual-workflow feature rather than a host security claim.
