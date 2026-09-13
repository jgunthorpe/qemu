# Patch 17: add the optional SMMUv3 guard

Proposed subject:

```text
hw/arm: Add a DRTM SMMUv3 DMA guard
```

Add an out-of-band translation deny state for strict mode only.

Changes:

- deny permissions before guest enable/bypass/stream-table processing;
- add an internal setter with IOTLB invalidation and listener notification;
- prevent guest MMIO from clearing the guard;
- coordinate reset and trace denied translations;
- expose the guard only to the strict-mode launch coordinator.

Qtests prime bypass/translated caches, activate the guard, verify immediate
read/write denial, and prove CPU RAM access continues.

Acceptance: this patch makes no claim about direct writers or basic mode.
