# Scope change: prioritize workflow emulation

> **Superseded scope note.** The final implementation retains the guest-visible
> software-contract boundary described here, but a TPM2 `tpm-tis-device`, PCR
> reset/extend operations, and DEN0113 v1.4B are now mandatory.  See
> [035-current-implementation.md](035-current-implementation.md).  SMMU/GIC
> enforcement remains intentionally outside the model.

The first planning pass treated a successful DRTM launch as a security claim
and therefore placed real TPM, complete DMA quiescing, SMMUv3, and GIC/ITS
work before VERSION and DYNAMIC_LAUNCH. The independent reviews in `030` and
`032` correctly identified what such a security-capable implementation would
need.

That is not the current project priority. The requested goal is now:

- emulate the DRTM SMC ABI and return values with useful fidelity;
- run the supplied DLME and Drtm.efi workflow inside QEMU;
- model protection/locality/interrupt state without guaranteeing enforcement;
- optionally connect the same workflow to QEMU's vTPM; and
- stop before SMMU/GIC/device-protection work unless it later becomes useful.

Accordingly, `003-patch-series.md` now has three phases. Patches 1-11 are the
primary deliverable. Patches 12-14 are an optional vTPM extension. Patches
15-19 preserve the earlier protection work as a final, independent strict-mode
proposal.

The following earlier review conditions are intentionally no longer blockers
for the basic mode:

- a real TPM/PCR measurement for every event;
- DMA-resistant measurement snapshots;
- SMMUv3 enforcement and draining retained mappings;
- fw_cfg DMA restrictions;
- GIC ITS/LPI quiescing; and
- post-boundary cold-reset remediation.

They remain valid requirements before a future strict mode claims those
security properties. The basic `x-drtm=on` documentation and trace points must
say that complete protection, TPM localities, and secure-interrupt effects are
modeled. This avoids confusing a successful ACS workflow with a secure DRTM
implementation.
