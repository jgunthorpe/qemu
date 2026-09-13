# Patch 10: add mutable TCB hashes

Proposed subject:

```text
hw/arm: Add mutable DRTM TCB hashes
```

Implement the remaining optional SET_TCB_HASH and LOCK_TCB_HASH SMC fidelity
without TPM or hardware-protection dependencies.

Changes:

- validate each call atomically, then append entries across calls;
- enforce advertised capacity and permit duplicate IDs per R315050;
- validate/normalize source bits, algorithm/digest sizes, reserved fields, and
  exact input consumption;
- return X1 populated count on success and the invalid entry on INVALID_DATA;
- make a second LOCK return DENIED and reject later mutation;
- define reset persistence and include accepted entries in metadata/events;
- advertise the functions and real capacity only in this patch.

Tests cover append, duplicates, zero/exact/over capacity, all X1 results,
atomic failure, locking, reset, and subsequent launch consumption. Run
Drtm.efi interface tests 12-14.

Acceptance: the SMC state machine and result registers match the selected
profile; no TPM command is sent.
