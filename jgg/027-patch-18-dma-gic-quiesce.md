# Patch 18: quiesce DMA and GIC in strict mode

Proposed subject:

```text
hw/arm: Quiesce DMA and GIC for DRTM launch
```

Cover strict-mode writes which an SMMUv3 translation check alone cannot stop.

Changes:

- stop submissions and drain allowlisted devices, block AIO, retained DMA
  mappings/rings, and queued ioeventfd work;
- quiesce ITS command/table writes and disable LPIs on every redistributor;
- confirm fw_cfg DMA is disabled/idle;
- define activation/restore ordering with the SMMUv3 guard;
- leave all of this code unreachable in basic workflow mode.

Tests hold virtio-blk AIO/mappings active, queue ITS/LPI work, and prove all
writes finish before the strict measurement snapshot and none occur after it.

Acceptance: the supported strict allowlist accounts for all virtual DMA paths.
