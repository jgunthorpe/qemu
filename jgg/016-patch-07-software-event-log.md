# Patch 7: build the software event log

Proposed subject:

```text
hw/arm: Build the DRTM software event log
```

Add deterministic modeled measurements for the workflow without a TPM.

Changes:

- use qcrypto SHA-256 rather than a local hash implementation;
- build a checked Spec ID Event03/PCR_EVENT2 stream;
- use the pinned ACS-compatible PCR indices, event order, separators, and
  non-distinct-DCE zero digest rule;
- measure copied DLME/DCE/configuration inputs under the BQL immediately before
  handoff;
- integrate the event section into patch 6's launch-data buffer;
- keep TPM-based hashing clear and make no claim that PCRs were extended.

Tests cover every event, digest, PCR index, order, exact-size boundary,
determinism, changed inputs, and independent SHA-256 vectors. Run the builder
portion of ACS tests 106, 113, and 116 once patch 9 exposes launch.

Acceptance: the event bytes are faithful to the workflow profile and the patch
does not include TPM frontend/backend code.
