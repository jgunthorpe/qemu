# Patch 5: decode launch parameters

Proposed subject:

```text
hw/arm: Decode DRTM launch parameters
```

Add a pure, fuzzable boundary for the untrusted revision-2 parameter block.

Changes:

- copy the 88-byte block once and decode explicit little-endian fields;
- add checked address/size, alignment, containment, and overlap helpers;
- validate revision/reserved bits, launch features, DLME region/image/entry,
  data offset, optional DCE, and protection table;
- verify referenced spans resolve to accessible ordinary guest RAM;
- return an immutable normalized descriptor and exact error code;
- let DYNAMIC_LAUNCH perform validation and then return NOT_SUPPORTED.

Tests table-drive truncated input, bad bits, every alignment/overlap rule,
RAM-to-MMIO spans, exact boundaries, zero sizes, and `UINT64_MAX` wrap. Add a
fuzz target for byte decoding and range helpers. Run ACS negative test 101 as
far as the current launch stub permits.

Acceptance: malformed input cannot crash QEMU or mutate service/guest state.
