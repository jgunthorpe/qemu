# Patch 16: define an optional strict topology

Proposed subject:

```text
hw/arm: Add a strict virt DRTM topology
```

Add opt-in restrictions used only by `x-drtm-hw-protection=on`.

Changes:

- require SMMUv3 with default-bus bypass disabled;
- require modern virtio PCI with `iommu_platform=on`;
- disable virtio-mmio transports and fw_cfg DMA or guard them explicitly;
- prohibit CPU/memory/device hotplug and non-allowlisted DMA masters;
- diagnose the exact incompatible device/option;
- leave ordinary `x-drtm=on` unrestricted and behaviorally unchanged.

Qtests cover every rejection and a minimal accepted strict topology.

Acceptance: strict restrictions cannot leak into the phase-1 workflow mode.
