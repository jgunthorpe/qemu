# Patch 9: implement the basic workflow launch

Proposed subject:

```text
hw/arm: Implement the DRTM workflow launch
```

Wire the service, parser, metadata, event log, and CPU helper into the first
complete Drtm.efi workflow. This is the primary implementation milestone.

Changes:

- validate caller/boot PE, require secondary PEs off, and enforce service
  lifecycle/launch-feature rules;
- copy and validate parameters and measured RAM;
- build/write launch data and the software event log;
- implement DYNAMIC_LAUNCH handoff with X0/X1 and validated PC;
- implement modeled UNPROTECT, CLOSE_LOCALITY, GET_ERROR, SET_ERROR, and repeat
  launch state transitions with exact return codes/registers;
- optionally model ENABLE_SECURE_INTERRUPTS state and its event without
  changing GIC state;
- publish mandatory function discovery and workflow FEATURES values;
- report modeled complete DMA protection so the ACS exercises the workflow,
  while emitting a trace/documentation warning that no DMA is blocked.

Failures return to the SMC caller with the specified modeled error. There is no
irreversible hardware boundary, TPM operation, device drain, or cold-reset
remediation in this mode.

Tests cover every state transition, error priority, repeated calls, non-boot
and secondary-PE cases, X0/X1/PC, exception masks, launch-data parsing, and
software digests. Run applicable Drtm.efi interface and dynamic tests 101-119,
recording image-auth/real-TPM/hardware-protection skips.

Acceptance: the ACS DLME runs and returns, UNPROTECT permits a later launch,
and default QEMU behavior remains unchanged when `x-drtm=off`.
