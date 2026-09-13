# Resolution of the post-review

> Historical note: the implementation gates below no longer block the basic
> emulation workflow. They remain gates for the optional strict hardware mode;
> see `034-emulation-scope.md`.

`032-post-review.md` judged the re-cut conditionally ready and found additional
details to close. The plans and runner were revised once more as follows.

| Post-review item | Resolution |
|---|---|
| TPM locality lifecycle | `001`, `005`, and patches 11-12 now require explicit locality 1/2/3/4 open, active, relinquish, close, reset and relaunch states. The DLME enters with locality 2 active, and CLOSE_LOCALITY distinguishes not-yet-relinquished from already closed. |
| Already-mapped/in-flight SMMU DMA | Patch 10 is now an all-master coordinator. It stops submissions and drains block AIO, persistent mappings/rings and queued ioeventfd work before activating/invalidation; patch 16 repeats this ordering at the boundary. |
| Version/profile source | The DEN0113 v1.1 audit remains an explicit, honest no-go gate in `005`; no guessed resolution was added. |
| Oversized publication patch | A new dormant patch 15 implements/tests mandatory state machines. Patch 16 is reduced to transaction coordination and atomic VERSION/FEATURES publication. The sequence now has 19 patches. |
| Runner TPM/pipeline/signal behavior | A QEMU DRTM property now requires `DRTM_SWTPM_SOCKET`; the fake-QEMU test verifies TPM arguments, both pipeline statuses are captured, ANSI/CR and empty/zero summaries are tested, and HUP/INT/TERM cleanup cases pass. |
| Post-PCR serialization | Patches 13-14 precompute capacity and validate static constraints. Final serialization is allocation-free; any remaining post-PCR error follows sticky-error cold-reset remediation. |

## Remaining implementation gates

Planning is complete enough to start non-ABI groundwork, but it intentionally
does not declare the whole project implementation-ready. The hard gates are:

1. obtain/audit DEN0113 v1.1, or switch the implementation and ACS to v1.4B;
2. prove/extend QEMU's TPM abstraction for the required HASH and locality
   semantics; and
3. design and test drain contracts for every device in the restricted DMA
   allowlist, especially persistent mappings and in-flight block AIO.

VERSION and successful launch remain behind all three gates in patch 16.
