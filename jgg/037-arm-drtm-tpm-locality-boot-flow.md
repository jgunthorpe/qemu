# TPM locality through an Arm DRTM boot flow

This note explains who is expected to own which TPM locality before, during,
and after an Arm Dynamic Root of Trust for Measurement (DRTM) launch.  Its
normative source is [Arm DEN0113, *Dynamic Root of Trust for Measurement*,
version 1.4B](./DEN0113_DRTM_1.4B.pdf).  Requirement IDs below are from that
document.  Observations about EDK2, the Arm DRTM ACS, and QEMU describe the
implementations in this workspace; they are not additional architectural
requirements.

For a driverless EFI launcher limited to the standard
`EFI_TCG2_PROTOCOL`, this analysis reaches one implementation conclusion:
firmware must acquire locality 0 for each TPM transaction and relinquish it
before that operation returns.  Inactivity between firmware TPM operations is
the only standard-interface state from which an arbitrary DRTM-capable EFI
loader can satisfy the launch precondition.

## The two independent locality state machines

The most important distinction is between **availability** and **current
ownership**:

- **Open/closed** is an Arm DRTM lifecycle property.  If a dynamic locality is
  closed, requests to acquire it are ignored.  The D-CRTM opens localities 1,
  2, and 3 at a Dynamic Launch Event.  Localities 2 and 3 can subsequently be
  closed.
- **Active/relinquished** is the TPM Platform Profile (PTP) arbitration state.
  An open locality can be inactive.  A caller normally requests a locality,
  uses it, finishes any command, and then relinquishes it.  Relinquishing
  removes current ownership; it does not close the locality.

Consequently:

- `command complete` does not imply `locality relinquished`;
- `locality relinquished` does not imply `locality closed`;
- `locality closed` necessarily prevents reacquisition, but closing is only
  allowed after the locality has been relinquished; and
- the DRTM launch precondition is **no active locality at all**, not merely
  "no TPM command executing."

`DRTM_CLOSE_LOCALITY` accepts only locality 2 or 3.  Its caller must first
relinquish that locality through the ordinary TPM interface; otherwise it
returns `DENIED` ([DEN0113 section 3.6, PDF pages
42-43](./DEN0113_DRTM_1.4B.pdf#page=42)).  This two-step operation is
deliberate: relinquishment ends ownership, while the DRTM service's close
operation prevents later reacquisition.

## Locality roles

| Locality | Role relevant to the boot flow | Access and lifecycle |
|---|---|---|
| 0 | No DRTM phase is assigned by DEN0113; ordinary pre-DRTM and post-DRTM traffic is governed by the TCG PTP | UEFI, a bootloader, or an OS will commonly use locality 0 for normal TPM commands.  It must not remain active across `DRTM_DYNAMIC_LAUNCH`. |
| 1 | A dynamic locality opened by the D-CRTM | DEN0113 requires support for and opening of locality 1, but does not assign it a concrete D-CRTM/DCE/DLME measurement phase or provide an architectural close call for it.  Do not invent a UEFI or bootloader ownership rule for locality 1. |
| 2 | DLME locality | It must already be active when control reaches the DLME.  The DLME can use it for its measurements, then must relinquish it before optionally closing it. |
| 3 | D-CRTM-after-HASH and DCE locality | The D-CRTM and DCE make launch measurements through it.  The DCE must relinquish and close it before entering the DLME. |
| 4 | D-CRTM-only dynamic-launch locality | The D-CRTM uses the PTP `HASH_START/HASH_DATA/HASH_END` path at locality 4 to reset the dynamic PCRs and seed PCR 17 with the DCE measurement.  Non-secure software must never be able to access it. |

This allocation comes from DEN0113 section 2.7: locality 4 starts the launch,
locality 3 continues the D-CRTM and DCE work, and locality 2 belongs to the
DLME ([PDF pages 26-27](./DEN0113_DRTM_1.4B.pdf#page=26)).  The security
boundary around locality 4 is mandatory: hardware must prevent Non-secure
access (R56020), and a hardware-backed D-CRTM must have exclusive locality-4
access (R64010 and R64180).

Localities are privilege/arbitration channels, not names for software layers.
It is therefore inaccurate to say that "UEFI owns locality 0" or "the
bootloader owns locality 1" as an architectural rule.  A particular UEFI or
bootloader implementation may acquire locality 0, but DEN0113 assigns the
DRTM phases only as shown above.

## End-to-end boot flow

```text
system reset
  L1/L2/L3 closed; no DRTM phase is active
       |
SRTM firmware -> UEFI -> boot manager/loader
  each ordinary TPM operation: acquire L0 -> command -> relinquish L0
  between operations: no locality active
       |
DCE preamble in the component initiating DRTM
  stop new TPM users; finish traffic; relinquish every locality
  REQUIRED boundary: no locality active
       |
DRTM_DYNAMIC_LAUNCH
  phase 1: D-CRTM verifies no locality active; may return DENIED
  phase 2: open L1/L2/L3; use L4 HASH sequence; continue on L3
       |
DCE
  use L3 -> relinquish L3 -> DRTM_CLOSE_LOCALITY(3)
  activate L2
       |
DLME entry
  L3 closed; L2 active
       |
DLME / post-DRTM runtime
  use L2 -> relinquish L2 -> optionally close L2
  ordinary runtime may later request L0
       |
repeat DRTM launch
  once again, no locality may be active
```

### 1. Reset and early firmware

A system-level reset must reset the TPM (R56050).  After reset, dynamic
localities 1, 2, and 3 are closed (R56070); the platform must provide a way
for the D-CRTM to open them during a later launch (R56080).  Closing is
enforced by the TPM mediation layer: writes that request a closed FIFO or CRB
locality are ignored, other registers behave as if no locality were active,
and the locality's command and response buffers are zeroed (R56060 and
R56065, [DEN0113 section 5.6.2, PDF page
90](./DEN0113_DRTM_1.4B.pdf#page=90)).

The ordinary measured-boot chain begins in the CRTM, proceeds through
firmware and UEFI to an OS loader, and measures those components into static
PCRs 0-15.  DEN0113 describes that SRTM chain but does not redefine the PTP
rules for its normal TPM commands ([sections 2.1-2.2, PDF pages
18-20](./DEN0113_DRTM_1.4B.pdf#page=18)).  In a typical PC-style TPM stack,
those commands use locality 0.

Locality 4 must be inaccessible to all Non-secure firmware from the start.
It is not a higher-priority escape hatch that UEFI or a bootloader can seize;
it is reserved to the trusted D-CRTM path.

### 2. UEFI

UEFI remains part of the SRTM boot chain.  Its TPM driver can acquire the
ordinary locality in order to initialize the TPM, measure drivers and
applications, service the EFI TCG2 protocol, or process physical-presence
operations.  TPM command state and locality arbitration state are independent:
after a synchronous command returns, the TPM can be idle while locality 0 is
still active.  Locality 0 becomes inactive only when the transport explicitly
relinquishes it.

DEN0113 gives UEFI two DRTM-related jobs, neither of which changes the launch
locality rule:

1. Before End of DXE, while all firmware is still under the platform
   manufacturer's authority, UEFI may supply required TCB hashes with
   `DRTM_SET_TCB_HASH`.
2. Before leaving that controlled phase, it must lock such hashes with
   `DRTM_LOCK_TCB_HASHES` (R41010 and R41050).

#### The required standard-EFI locality model

`EFI_TCG2_PROTOCOL` exposes TPM command submission, measurement, event-log,
and PCR-bank operations.  It exposes no operation to query, quiesce, acquire,
or relinquish a PTP locality.  Relinquishment cannot be encoded with
`SubmitCommand()` because it is a FIFO/TIS or CRB transport-register operation,
not a TPM 2 command.  Calling `ExitBootServices()` is not a substitute: UEFI
can make final TPM measurements during that transition, and the EDK2 path in
this tree does not relinquish locality afterward.

Under the constraints relevant to a generic ACS EFI stub--only the standard
EFI interfaces and no TPM transport driver in the stub--the only workable
Arm-compliant operating model is for the firmware TPM stack to treat locality
ownership as a lease around every TPM transaction:

```text
no locality active
    -> acquire locality 0
    -> execute one complete TPM transaction
    -> return the FIFO/TIS or CRB interface to idle
    -> relinquish locality 0
no locality active
```

The lease must be implemented at the lowest common firmware TPM transport
layer, not merely around the public `EFI_TCG2_PROTOCOL.SubmitCommand()` entry
point.  EFI operations such as `HashLogExtendEvent`, boot measurements,
physical-presence handling, and ExitBootServices measurements can reach the
same lower-level `Tpm2SubmitCommand()` path without calling the public
`SubmitCommand()` method.

This model does not invalidate TPM objects or authorization sessions.  They
are TPM-resident state and do not require uninterrupted PTP ownership between
commands.  A later command reacquires locality 0 and continues normally;
locality-dependent authorization still observes locality 0 while that command
executes.

To maintain the invariant, the firmware implementation must:

1. serialize acquisition, command execution, cleanup, and relinquishment with
   one lock;
2. relinquish on every completion and error path on which the transport can be
   returned safely to idle;
3. report a wedged, timed-out, queued, or aborting transaction as not ready for
   DRTM rather than pretending that a release write succeeded; and
4. prevent asynchronous callbacks or another PE from acquiring a locality in
   the interval between the last firmware operation and the launch SMC.

If a UEFI application, bootloader, or OS loader invokes
`DRTM_DYNAMIC_LAUNCH`, it acts as the **DCE preamble**.  With per-operation
leasing, its last synchronous EFI TCG2 call returns with no locality active.
It must then suppress new EFI callbacks, turn off the secondary PEs, and issue
the launch SMC without allowing another TPM operation in between.  The D-CRTM
still performs the mandatory R44060 check.

A platform-specific `PrepareForDrtm()` EFI protocol could instead quiesce a
firmware stack that deliberately retains locality 0.  That is a different,
non-standard platform contract and a generic ACS stub cannot rely on it.
Without such an extension or direct transport access in the stub,
per-operation firmware leasing is the only available flow.

### 3. Boot manager, bootloader, or OS loader

DEN0113 calls a Normal-world OS loader initiating DRTM after loading the OS
images a typical scenario (section 2.4).  The concrete executable might be a
UEFI application, a boot manager, a bootloader such as GRUB, or an OS-specific
loader.  Its name does not determine its locality.  The component that
actually calls `DRTM_DYNAMIC_LAUNCH` owns the complete DCE-preamble
responsibility.

That preamble must:

- prepare the DLME image, data, parameters, and memory-protection request;
- turn off every PE except the boot PE; and
- ensure that **no TPM locality is active at the instant of launch**
  (R42120, [DEN0113 section 4.2, PDF page
  68](./DEN0113_DRTM_1.4B.pdf#page=68)).

With the standard-EFI leasing model, the launch-boundary sequence is:

1. complete the last synchronous EFI TCG2 operation; the firmware transport
   returns its interface to idle and relinquishes locality 0 before returning;
2. prevent UEFI callbacks, interrupt paths, and other PEs from beginning a new
   TPM operation; and
3. issue the SMC immediately, relying on the D-CRTM to verify that no locality
   is active.

The EFI stub cannot itself perform the stronger read-back check through
`EFI_TCG2_PROTOCOL`, because that protocol exposes neither locality state nor
the transport register map.  The firmware transport must enforce the
no-active-locality postcondition, and the architectural D-CRTM check is the
authoritative enforcement at launch.  Hard-coding a locality-0 TIS address in
generic ACS code would fail on CRB, hardware-enclave, and Secure-world TPM
implementations permitted by DEN0113.

### 4. `DRTM_DYNAMIC_LAUNCH` and D-CRTM phase 1

The SMC crosses a security boundary; it does not absolve the caller from the
preamble.  In a firmware-backed implementation, the D-CRTM independently
verifies that no TPM locality is active.  If one is active, it must return
`DENIED`; an access failure returns `TPM_ERROR` (R44060, [DEN0113 section 4.4,
PDF page 69](./DEN0113_DRTM_1.4B.pdf#page=69)).  A hardware-backed
implementation performs the analogous returnable check in R62012 and checks
again inside the D-CRTM in R62070.

The locality check belongs to the returnable, no-state-change phase.  If it
fails, localities 1-3 and the rest of the platform state must be left
unmodified (R44070 and R44075).  DEN0113 requires both the locality and
parameter checks but does not explicitly specify which error wins when both
preconditions are false.  QEMU performs the locality check first, so on QEMU
an active locality masks an otherwise expected `INVALID_PARAMETERS` result
with `DENIED`.

### 5. D-CRTM phase 2

Once returnable checks have passed, the D-CRTM establishes the dynamic TPM
environment:

1. It opens localities 1, 2, and 3 using a platform-specific mechanism
   (R44100).
2. It performs `HASH_START`, DCE digest `HASH_DATA`, and `HASH_END` at
   locality 4 (R44090).  `HASH_START` resets the dynamic PCRs and the complete
   sequence establishes the first PCR 17 measurement.
3. It continues the launch using locality 3 and measures the required D-CRTM,
   DCE, configuration, and schema state.

These are trusted platform actions, not guest requests for locality 4.  With
firmware-backed DRTM a Secure TPM service commonly mediates them; with
hardware-backed DRTM the coprocessor has the exclusive locality-4 path.
DEN0113 specifies the firmware-backed requirements in Table 25 and a distinct
hardware-backed order in Table 62; implementations must not assume that the
two internal sequences are interchangeable.

### 6. DCE handoff to the DLME

The DCE uses locality 3 for its measurements.  Before transferring control to
the DLME it must satisfy both of these requirements:

- locality 3 is closed (R45330); and
- locality 2 is active (R45340).

The required locality-3 transition is therefore:

```text
L3 active -> finish TPM transaction -> relinquish L3
          -> DRTM_CLOSE_LOCALITY(3) -> L3 closed
          -> platform activates L2 -> enter DLME
```

`DRTM_CLOSE_LOCALITY(3)` is not the relinquish operation.  Calling it while
locality 3 remains active must fail.  Conversely, stopping after relinquish
would leave locality 3 open and reacquirable, violating R45330.  See the DCE
handoff requirements in [DEN0113 section 4.5, PDF page
75](./DEN0113_DRTM_1.4B.pdf#page=75).

### 7. DLME and post-DRTM runtime

The DLME starts with locality 2 already active; it must not request it again.
It may use locality 2 for implementation- or OS-specific measurements, with
PCRs 19-22 reserved for the DLME.  It must treat unvalidated pre-DRTM code,
including UEFI Runtime Services, as outside the newly established TCB
([DEN0113 section 4.6, PDF pages
78-80](./DEN0113_DRTM_1.4B.pdf#page=78)).

When the DLME is finished measuring, it has two policy choices:

- **Relinquish and close locality 2.**  This is required if the system's
  security policy needs to prevent further measurements into PCRs 17 and 18.
  The DLME first relinquishes locality 2 through PTP and then calls
  `DRTM_CLOSE_LOCALITY(2)`.
- **Relinquish but leave locality 2 open.**  DEN0113 makes closing locality 2
  optional.  Relinquishment is still necessary before another locality can be
  used cleanly and before a repeated DRTM launch can pass the no-active-
  locality precondition.

After locality 2 is relinquished, the post-DRTM OS may request locality 0 for
ordinary TPM services.  Before any later dynamic launch, the new DCE preamble
must once again quiesce those services and relinquish locality 0.  R43010
requires repeated dynamic launches without a system reset; R42120 means every
such launch must still cross the same no-active-locality boundary.  At the
next DL Event the D-CRTM reopens localities 1-3, including any locality 2 that
the preceding DLME closed.

## What this means for the current EDK2/ACS/QEMU path

The current test flow is:

```text
QEMU reset -> EDK2 -> EFI shell -> Drtm.efi -> dynamic-launch SMC
```

Three implementation facts matter:

1. EDK2's `Tcg2Dxe` calls `Tpm2RequestUseTpm()` at driver entry.  The FIFO/TIS
   helper requests the locality by writing `requestUse`, and the relevant
   EDK2 device-library path in this tree has no matching relinquish API.  A
   traced test-101 boot confirms that QEMU activates locality 0 during EDK2
   boot and observes no release before the launch SMC.
2. The ACS `val_drtm_dynamic_launch()` wrapper calls
   `val_drtm_simulate_dl()`.  That assembly saves state, flushes caches, and
   issues the SMC, but performs no TPM quiesce/relinquish preamble.
3. QEMU checks the real TPM frontend before decoding `DRTM_PARAMETERS`.
   `tpm_tis_drtm_no_active_locality()` reports false for any valid active
   locality, an active platform command, a busy/queued/aborting or
   locality-switching guest transaction, or an in-progress DRTM PTP hash
   sequence.  The launch service then returns `DENIED` before parameter
   decoding.

QEMU's broader predicate is a serialization-safe interpretation of "no
active locality": checking only the visible `activeLocality` bit would race
with a command completion, queued request, abort, locality switch, or
`HASH_START/HASH_END` sequence.  It also explains why reading locality 0 alone
is useful but not sufficient for a final diagnosis.

The generic ACS UEFI PAL cannot repair this through the standard TCG2
protocol: it has neither a release call nor enough transport information to
implement one portably.  The proper fix for this boot path is therefore in the
EDK2 TPM transport:

1. replace initialization-time permanent acquisition with acquire/use/idle/
   relinquish around every lower-level TPM transaction;
2. ensure every EFI TCG2 operation returns only after locality 0 is
   relinquished, or returns an error stating that the TPM is not DRTM-ready;
3. serialize firmware TPM users so no queued request receives locality
   immediately after release; and
4. ensure the DCE preamble suppresses new callbacks and other PEs between its
   final EFI operation and the SMC.

Negative ACS tests then need no special reacquisition cleanup.  When a
returnable DRTM failure leaves locality state unmodified, the next EFI TCG2
operation acquires locality 0 for itself and relinquishes it again before
returning.  This is the principal practical benefit of making inactivity the
firmware interface's stable state.

## Diagnostic checklist at the launch boundary

Immediately before the SMC, record:

- the interface type and locality register base used by the platform;
- FIFO/TIS `TPM_ACCESS_x` or CRB locality state/control for every exposed
  locality, especially locality 0;
- whether a locality is assigned, active, requested, or being seized;
- whether a TPM command is executing, completing, queued, or aborting; and
- QEMU trace state for `active_locty`, `next_locty`, `aborting_locty`, the
  guest/platform command paths, and the DRTM hash sequence.

The expected snapshots are:

| Boundary | Required/expected locality state |
|---|---|
| After reset | L1-L3 closed; L0 follows the ordinary PTP/reset rules rather than the DRTM close lifecycle |
| During a UEFI/SRTM TPM operation | L0 active only for the duration of that serialized transaction |
| Between completed EFI TPM operations | No locality active |
| Immediately before `DRTM_DYNAMIC_LAUNCH` | No locality active and no TPM operation capable of retaining or immediately transferring ownership |
| D-CRTM/DCE measurement phase | L1-L3 open; L4 used only by D-CRTM HASH; L3 used by D-CRTM/DCE |
| DLME entry | L3 closed; L2 active |
| Stable post-DRTM runtime | L2 relinquished and optionally closed; L0 may be reacquired for ordinary OS traffic |
| Before a repeated launch | No locality active again |

This evidence distinguishes an unrelinquished locality 0 from another source
of `DENIED`, and distinguishes both from malformed launch parameters that can
only be tested after the locality precondition succeeds.
